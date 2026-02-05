import * as fs from 'fs/promises';
import * as path from 'path';

export async function ensureDirectory(dirPath: string): Promise<void> {
  try {
    await fs.access(dirPath);
  } catch {
    await fs.mkdir(dirPath, { recursive: true });
  }
}

export async function writeJsonFile(filePath: string, data: any): Promise<void> {
  await ensureDirectory(path.dirname(filePath));
  await fs.writeFile(filePath, JSON.stringify(data, null, 2), 'utf-8');
}

export async function readJsonFile(filePath: string): Promise<any> {
  const content = await fs.readFile(filePath, 'utf-8');
  return JSON.parse(content);
}

export async function copyFile(source: string, destination: string): Promise<void> {
  await ensureDirectory(path.dirname(destination));
  await fs.copyFile(source, destination);
}

export function getFileExtension(fileName: string): string {
  return path.extname(fileName).toLowerCase().slice(1);
}

export function isTextFile(fileName: string): boolean {
  const textExtensions = ['js', 'ts', 'jsx', 'tsx', 'py', 'java', 'go', 'rb', 'php', 'html', 'css', 'scss', 'json', 'xml', 'yml', 'yaml', 'md', 'txt'];
  const ext = getFileExtension(fileName);
  return textExtensions.includes(ext);
}
