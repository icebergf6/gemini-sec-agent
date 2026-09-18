import fs from 'fs/promises';
import path from 'path';

export const declaration = {
  name: 'code_patcher',
  description: 'Overpower surgical code patcher: replace/overwrite/append/prepend/insert/delete/restore/diff operations, auto-timestamped .bak, dry-run mode, multi-occurrence support, and smart search with regex.',
  parameters: {
    type: 'OBJECT',
    properties: {
      filePath:           { type: 'STRING',  description: 'Target file path (absolute or relative to cwd)' },
      operation:          { type: 'STRING',  description: '"replace" | "overwrite" | "append" | "prepend" | "insert_after" | "insert_before" | "delete_line" | "restore" | "diff" | "list_backups"' },
      targetString:       { type: 'STRING',  description: 'Exact text to find (for replace/insert_after/insert_before/delete_line)' },
      replacementContent: { type: 'STRING',  description: 'New content to inject (for replace/overwrite/append/prepend/insert)' },
      lineNumber:         { type: 'INTEGER', description: 'Line number for line-specific operations (1-indexed)' },
      replaceAll:         { type: 'BOOLEAN', description: 'Replace ALL occurrences (for replace operation, default: false)' },
      useRegex:           { type: 'BOOLEAN', description: 'Treat targetString as a regex pattern (default: false)' },
      dryRun:             { type: 'BOOLEAN', description: 'Preview changes without writing to disk (default: false)' },
      backupPath:         { type: 'STRING',  description: 'Specific .bak file to restore from (for restore operation)' },
      encoding:           { type: 'STRING',  description: 'File encoding (default: utf8)' },
    },
    required: ['filePath', 'operation']
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────────────────────
function timestamp() {
  const d=new Date(), pad=n=>String(n).padStart(2,'0');
  return `${d.getFullYear()}${pad(d.getMonth()+1)}${pad(d.getDate())}_${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}`;
}

async function createBackup(filePath, content, encoding) {
  const bakPath = `${filePath}.${timestamp()}.bak`;
  await fs.writeFile(bakPath, content, encoding);
  return bakPath;
}

function diffPreview(original, modified) {
  const oLines = original.split('\n');
  const mLines = modified.split('\n');
  const out = [];
  const max = Math.max(oLines.length, mLines.length);
  let changes = 0;
  for (let i=0; i<max; i++) {
    const o = oLines[i], m = mLines[i];
    if (o !== m) {
      changes++;
      if (o !== undefined) out.push(`- [L${i+1}] ${o}`);
      if (m !== undefined) out.push(`+ [L${i+1}] ${m}`);
    }
  }
  return { changes, preview: out.slice(0,40).join('\n'), truncated: out.length > 40 };
}

// ─────────────────────────────────────────────────────────────────────────────
// OPERATIONS
// ─────────────────────────────────────────────────────────────────────────────
export async function execute(args) {
  const filePath  = path.resolve(process.cwd(), args.filePath);
  const op        = (args.operation||'replace').toLowerCase();
  const encoding  = args.encoding || 'utf8';
  const dryRun    = Boolean(args.dryRun);

  // ── LIST BACKUPS ─────────────────────────────────────────────────────────────
  if (op === 'list_backups') {
    try {
      const dir     = path.dirname(filePath);
      const base    = path.basename(filePath);
      const entries = await fs.readdir(dir);
      const baks    = entries
        .filter(e=>e.startsWith(base)&&e.endsWith('.bak'))
        .sort().reverse();
      return {
        success:     true,
        targetFile:  filePath,
        backupCount: baks.length,
        backups:     baks.map(b=>path.join(dir,b))
      };
    } catch(e) { return { success:false, error:`Cannot list backups: ${e.message}` }; }
  }

  // ── RESTORE ──────────────────────────────────────────────────────────────────
  if (op === 'restore') {
    let bakPath = args.backupPath;
    if (!bakPath) {
      const dir   = path.dirname(filePath);
      const base  = path.basename(filePath);
      const all   = (await fs.readdir(dir)).filter(e=>e.startsWith(base)&&e.endsWith('.bak')).sort().reverse();
      if (!all.length) return { success:false, error:`No .bak files found for ${filePath}` };
      bakPath = path.join(dir,all[0]);
    }
    try {
      const bakContent = await fs.readFile(bakPath, encoding);
      if (!dryRun) await fs.writeFile(filePath, bakContent, encoding);
      return {
        success: true,
        dryRun,
        restoredFrom: bakPath,
        targetFile:   filePath,
        message: dryRun ? `[DRY RUN] Would restore from ${bakPath}` : `Restored from ${bakPath}`
      };
    } catch(e) { return { success:false, error:`Restore failed: ${e.message}` }; }
  }

  // ── DIFF (compare latest backup vs current) ──────────────────────────────────
  if (op === 'diff') {
    try {
      const dir   = path.dirname(filePath);
      const base  = path.basename(filePath);
      const all   = (await fs.readdir(dir)).filter(e=>e.startsWith(base)&&e.endsWith('.bak')).sort().reverse();
      if (!all.length) return { success:false, error:'No backup found to diff against.' };
      const [current, backup] = await Promise.all([
        fs.readFile(filePath, encoding),
        fs.readFile(path.join(dir,all[0]), encoding)
      ]);
      const { changes, preview } = diffPreview(backup, current);
      return { success:true, targetFile:filePath, latestBackup:path.join(dir,all[0]), changedLines:changes, diff:preview };
    } catch(e) { return { success:false, error:e.message }; }
  }

  // ── READ FILE ─────────────────────────────────────────────────────────────────
  let original;
  try { original = await fs.readFile(filePath, encoding); }
  catch(e) { return { success:false, error:`Cannot read file: ${e.message}` }; }

  let modified = original;

  // ── APPLY OPERATION ───────────────────────────────────────────────────────────
  if (op === 'overwrite') {
    if (args.replacementContent === undefined)
      return { success:false, error:'replacementContent required for overwrite.' };
    modified = args.replacementContent;

  } else if (op === 'append') {
    if (args.replacementContent === undefined)
      return { success:false, error:'replacementContent required for append.' };
    modified = original + args.replacementContent;

  } else if (op === 'prepend') {
    if (args.replacementContent === undefined)
      return { success:false, error:'replacementContent required for prepend.' };
    modified = args.replacementContent + original;

  } else if (op === 'replace') {
    const target = args.targetString;
    if (!target) return { success:false, error:'targetString required for replace.' };
    const repl   = args.replacementContent ?? '';
    if (args.useRegex) {
      try {
        const flags = args.replaceAll ? 'g' : '';
        modified = original.replace(new RegExp(target, flags), repl);
      } catch(e) { return { success:false, error:`Invalid regex: ${e.message}` }; }
    } else {
      if (!original.includes(target))
        return { success:false, error:`targetString not found in file. No changes made.`, tip:'Use /run code_patcher diff to compare.' };
      modified = args.replaceAll
        ? original.split(target).join(repl)
        : original.replace(target, repl);
    }

  } else if (op === 'insert_after') {
    const target = args.targetString;
    if (!target) return { success:false, error:'targetString required for insert_after.' };
    if (!original.includes(target))
      return { success:false, error:'targetString not found.' };
    modified = original.replace(target, target + (args.replacementContent||''));

  } else if (op === 'insert_before') {
    const target = args.targetString;
    if (!target) return { success:false, error:'targetString required for insert_before.' };
    if (!original.includes(target))
      return { success:false, error:'targetString not found.' };
    modified = original.replace(target, (args.replacementContent||'') + target);

  } else if (op === 'delete_line') {
    const lines = original.split('\n');
    if (args.lineNumber) {
      const ln = args.lineNumber - 1;
      if (ln < 0 || ln >= lines.length) return { success:false, error:`Line ${args.lineNumber} out of range (file has ${lines.length} lines).` };
      lines.splice(ln, 1);
      modified = lines.join('\n');
    } else if (args.targetString) {
      const filtered = lines.filter(l=>!l.includes(args.targetString));
      const deleted  = lines.length - filtered.length;
      if (deleted === 0) return { success:false, error:'targetString not found on any line.' };
      modified = filtered.join('\n');
    } else {
      return { success:false, error:'Provide lineNumber or targetString for delete_line.' };
    }

  } else {
    return { success:false, error:`Unknown operation: "${op}". Valid: replace|overwrite|append|prepend|insert_after|insert_before|delete_line|restore|diff|list_backups` };
  }

  // ── DRY RUN PREVIEW ───────────────────────────────────────────────────────────
  if (dryRun) {
    const { changes, preview } = diffPreview(original, modified);
    return {
      success: true,
      dryRun:  true,
      targetFile: filePath,
      operation:  op,
      changedLines: changes,
      diffPreview:  preview,
      message: `[DRY RUN] ${changes} line(s) would change. Run without dryRun:true to apply.`
    };
  }

  // ── CREATE BACKUP ─────────────────────────────────────────────────────────────
  let bakPath;
  try { bakPath = await createBackup(filePath, original, encoding); }
  catch(e) { return { success:false, error:`Backup failed: ${e.message}. Aborting.` }; }

  // ── WRITE PATCHED FILE ────────────────────────────────────────────────────────
  try {
    await fs.writeFile(filePath, modified, encoding);
    const { changes, preview } = diffPreview(original, modified);
    return {
      success:    true,
      targetFile: filePath,
      operation:  op,
      backupCreated: bakPath,
      originalLines: original.split('\n').length,
      newLines:       modified.split('\n').length,
      changedLines:   changes,
      diffPreview:    preview,
      message: `✔ Patch applied. Backup: ${path.basename(bakPath)}. Changed ${changes} line(s).`
    };
  } catch(e) {
    // Emergency rollback
    try { await fs.writeFile(filePath, original, encoding); } catch {}
    return { success:false, error:`Write failed: ${e.message}. File rolled back.` };
  }
}
