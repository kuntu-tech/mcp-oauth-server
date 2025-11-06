import crypto from "crypto";
import bcrypt from "bcryptjs";

export const hashPassword = (password: string): string => {
  return bcrypt.hashSync(password, 12);
};

export const verifyPassword = (password: string, hash: string): boolean => {
  return bcrypt.compareSync(password, hash);
};

export const createRandomPassword = (): string => {
  return crypto.randomBytes(24).toString("hex");
};

