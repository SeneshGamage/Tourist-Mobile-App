export const ACCOUNT_ROLES = ['TOURIST', 'GUIDE', 'VRSP'] as const;

export type AccountRole = (typeof ACCOUNT_ROLES)[number];

export interface AuthenticatedUser {
  id: string;
  email: string;
  role: AccountRole;
}

export interface JwtPayload {
  sub: string;
  email: string;
  role: AccountRole;
}