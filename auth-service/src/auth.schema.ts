import { z } from "zod";

export const AuthRequestSchema = z.object({
  username: z.string().min(3, "Username must be at least 3 chars"),
  password: z.string().min(6, "Password must be at least 6 chars"),
});

export const RefreshRequestSchema = z.object({
  refreshToken: z.string(),
});
// Login response schema
export const TokenResponseSchema = z.object({
  accessToken: z.string(),
  refreshToken: z.string(),
});

//! using refine instead of using direct function
export const RegisterRequestSchema = z.object({
  username: z.string(),
  password: z.string()
}).refine((data) => data.username.length >= 3, {
  path: ["username"],
  message: "Username must be at least 3 chars"
}).refine((data) => data.password.length >= 6, {
  path: ["password"],
  message: "Password must be at least 6 chars"
});

//! Equivalent of: export type RegisterRequestBody = z.infer<typeof RegisterRequestSchema>;
export interface RegisterRequestBody {
  username: string;
  password: string;
}

//! Equivalent of: export type AuthRequestDTO = z.infer<typeof AuthRequestSchema>;
export interface AuthRequestDTO {
  username: string;
  password: string;
}

//! Equivalent of: export type TokenResponseDTO = z.infer<typeof TokenResponseSchema>;
export interface TokenResponseDTO {
  accessToken: string;
  refreshToken: string;
}

