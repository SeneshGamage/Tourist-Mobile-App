import type { RequestHandler, Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

import { env } from '../../config/env';
import {
  ACCOUNT_ROLES,
  type AccountRole,
  type AuthenticatedUser
} from './auth.types';

export const authenticate: RequestHandler = (req: Request, res: Response, next: NextFunction) => {
  const authorization = req.get('authorization');

  if (!authorization || !authorization.startsWith('Bearer ')) {
    res.status(401).json({
      success: false,
      message: 'Authentication token is required.'
    });
    return;
  }

  const token = authorization.slice(7).trim();

  if (!token) {
    res.status(401).json({
      success: false,
      message: 'Authentication token is required.'
    });
    return;
  }

  try {
    const decoded = jwt.verify(token, env.JWT_ACCESS_SECRET);

    if (typeof decoded === 'string') {
      res.status(401).json({
        success: false,
        message: 'Invalid authentication token.'
      });
      return;
    }

    const { sub, email, role } = decoded;

    const validRole =
      typeof role === 'string' &&
      (ACCOUNT_ROLES as readonly string[]).includes(role);

    if (
      typeof sub !== 'string' ||
      typeof email !== 'string' ||
      !validRole
    ) {
      res.status(401).json({
        success: false,
        message: 'Invalid authentication token.'
      });
      return;
    }

    const user: AuthenticatedUser = {
      id: sub,
      email,
      role: role as AccountRole
    };

    req.authUser = user;

    next();
  } catch {
    res.status(401).json({
      success: false,
      message: 'Invalid or expired authentication token.'
    });
  }
};

export function authorizeRoles(
  ...allowedRoles: AccountRole[]
): RequestHandler {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.authUser) {
      res.status(401).json({
        success: false,
        message: 'Authentication is required.'
      });
      return;
    }

    if (!allowedRoles.includes(req.authUser.role)) {
      res.status(403).json({
        success: false,
        message: 'You do not have permission to access this resource.'
      });
      return;
    }

    next();
  };
}