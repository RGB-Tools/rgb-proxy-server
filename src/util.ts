import fs from "fs";

// If dir doesn't exist we create it
const setDir = (dir: string): string => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir);

  return dir;
};

export { setDir };
