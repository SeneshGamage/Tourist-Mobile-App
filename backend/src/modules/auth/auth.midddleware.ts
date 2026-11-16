
import { RequestHandler } from 'express';
import jwt from 'jsonwebtoken';

import { env } from '../../config/env';
import { AuthenticatedUser, ACCOUNT_ROLES } from './auth.types';

export const authenticate: RequestHandler = (
  req,
  res,
  next
) => {
  const authorization = req.headers.authorization;

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
    const decoded = jwt.verify(
      token,
      env.JWT_ACCESS_SECRET
    );

    if (
      typeof decoded === 'string' ||
      !decoded.sub ||
      !decoded.email ||
      !ACCOUNT_ROLES.includes(decoded.role as any)
    ) {
      res.status(401).json({
        success: false,
        message: 'Invalid authentication token.'
      });
      return;
    }

    const user: AuthenticatedUser = {
      id: decoded.sub,
      email: decoded.email,
      role: decoded.role as AuthenticatedUser['role']
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
  ...allowedRoles: AuthenticatedUser['role'][]
): RequestHandler {
  return (req, res, next) => {
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
