import bcrypt from 'bcryptjs';
import jwt, { type SignOptions } from 'jsonwebtoken';
import { Prisma } from '@prisma/client';

import { prisma } from '../../config/prisma';
import { env } from '../../config/env';

import {
  type AccountRole,
  type AuthenticatedUser,
  type JwtPayload
} from './auth.types';

import {
  type RegisterInput,
  type LoginInput
} from './auth.schemas';

export class AuthError extends Error {
  constructor(
    message: string,
    public statusCode: number
  ) {
    super(message);
    this.name = 'AuthError';
  }
}

const SALT_ROUNDS = 12;

function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

function createAccessToken(user: AuthenticatedUser): string {
  const payload: JwtPayload = {
    sub: user.id,
    email: user.email,
    role: user.role
  };

  return jwt.sign(payload, env.JWT_ACCESS_SECRET, {
    expiresIn: env.JWT_ACCESS_EXPIRES_IN as SignOptions['expiresIn']
  });
}

function toAuthenticatedUser(
  id: string,
  email: string,
  role: AccountRole
): AuthenticatedUser {
  return { id, email, role };
}

async function emailAlreadyExists(email: string): Promise<boolean> {
  const [tourist, guide, provider] = await Promise.all([
    prisma.tourist.findUnique({
      where: { email },
      select: { touristId: true }
    }),

    prisma.guide.findUnique({
      where: { email },
      select: { guideId: true }
    }),

    prisma.vRSP.findUnique({
      where: { email },
      select: { vrspId: true }
    })
  ]);

  return Boolean(tourist || guide || provider);
}

export async function registerAccount(input: RegisterInput) {
  const email = normalizeEmail(input.email);

  if (await emailAlreadyExists(email)) {
    throw new AuthError(
      'An account with this email already exists.',
      409
    );
  }

  const passwordHash = await bcrypt.hash(
    input.password,
    SALT_ROUNDS
  );

  try {
    let user!: AuthenticatedUser;

    switch (input.role) {
      case 'TOURIST': {
        const account = await prisma.tourist.create({
          data: {
            fullName: input.fullName!,
            email,
            passwordHash,
            phone: input.phone
          },
          select: {
            touristId: true,
            email: true
          }
        });

        user = toAuthenticatedUser(
          account.touristId,
          account.email,
          'TOURIST'
        );

        break;
      }

      case 'GUIDE': {
        const account = await prisma.guide.create({
          data: {
            fullName: input.fullName!,
            email,
            passwordHash,
            phone: input.phone
          },
          select: {
            guideId: true,
            email: true
          }
        });

        user = toAuthenticatedUser(
          account.guideId,
          account.email,
          'GUIDE'
        );

        break;
      }

      case 'VRSP': {
        const account = await prisma.vRSP.create({
          data: {
            businessName: input.businessName!,
            email,
            passwordHash,
            phone: input.phone
          },
          select: {
            vrspId: true,
            email: true
          }
        });

        user = toAuthenticatedUser(
          account.vrspId,
          account.email,
          'VRSP'
        );

        break;
      }
    }

    return {
      user,
      accessToken: createAccessToken(user)
    };
  } catch (error) {
    if (
      error instanceof Prisma.PrismaClientKnownRequestError &&
      (error as Prisma.PrismaClientKnownRequestError).code === 'P2002'
    ) {
      throw new AuthError(
        'An account with this email already exists.',
        409
      );
    }

    throw error;
  }
}

export async function loginAccount(input: LoginInput) {
  const email = normalizeEmail(input.email);

  let account:
    | { id: string; email: string; passwordHash: string }
    | null = null;

  switch (input.role) {
    case 'TOURIST': {
      const result = await prisma.tourist.findUnique({
        where: { email },
        select: {
          touristId: true,
          email: true,
          passwordHash: true
        }
      });

      if (result) {
        account = {
          id: result.touristId,
          email: result.email,
          passwordHash: result.passwordHash
        };
      }

      break;
    }

    case 'GUIDE': {
      const result = await prisma.guide.findUnique({
        where: { email },
        select: {
          guideId: true,
          email: true,
          passwordHash: true
        }
      });

      if (result) {
        account = {
          id: result.guideId,
          email: result.email,
          passwordHash: result.passwordHash
        };
      }

      break;
    }

    case 'VRSP': {
      const result = await prisma.vRSP.findUnique({
        where: { email },
        select: {
          vrspId: true,
          email: true,
          passwordHash: true
        }
      });

      if (result) {
        account = {
          id: result.vrspId,
          email: result.email,
          passwordHash: result.passwordHash
        };
      }

      break;
    }
  }

  if (!account) {
    throw new AuthError('Invalid email or password.', 401);
  }

  const passwordMatches = await bcrypt.compare(
    input.password,
    account.passwordHash
  );

  if (!passwordMatches) {
    throw new AuthError('Invalid email or password.', 401);
  }

  const user = toAuthenticatedUser(
    account.id,
    account.email,
    input.role
  );

  return {
    user,
    accessToken: createAccessToken(user)
  };
}

export async function getAuthenticatedAccount(
  user: AuthenticatedUser
) {
  switch (user.role) {
    case 'TOURIST': {
      const account = await prisma.tourist.findUnique({
        where: { touristId: user.id },
        select: {
          touristId: true,
          fullName: true,
          email: true,
          phone: true,
          profilePicture: true,
          createdAt: true
        }
      });

      if (!account) return null;

      return {
        id: account.touristId,
        role: 'TOURIST' as const,
        fullName: account.fullName,
        email: account.email,
        phone: account.phone,
        profilePicture: account.profilePicture,
        createdAt: account.createdAt
      };
    }

    case 'GUIDE': {
      const account = await prisma.guide.findUnique({
        where: { guideId: user.id },
        select: {
          guideId: true,
          fullName: true,
          email: true,
          phone: true,
          profilePicture: true,
          isVerified: true,
          createdAt: true
        }
      });

      if (!account) return null;

      return {
        id: account.guideId,
        role: 'GUIDE' as const,
        fullName: account.fullName,
        email: account.email,
        phone: account.phone,
        profilePicture: account.profilePicture,
        isVerified: account.isVerified,
        createdAt: account.createdAt
      };
    }

    case 'VRSP': {
      const account = await prisma.vRSP.findUnique({
        where: { vrspId: user.id },
        select: {
          vrspId: true,
          businessName: true,
          email: true,
          phone: true,
          profilePicture: true,
          isVerified: true,
          createdAt: true
        }
      });

      if (!account) return null;

      return {
        id: account.vrspId,
        role: 'VRSP' as const,
        businessName: account.businessName,
        email: account.email,
        phone: account.phone,
        profilePicture: account.profilePicture,
        isVerified: account.isVerified,
        createdAt: account.createdAt
      };
    }
  }
}