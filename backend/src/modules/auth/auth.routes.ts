import { Router, type RequestHandler } from 'express';
import { ZodError } from 'zod';

import {
  registerSchema,
  loginSchema
} from './auth.schemas';

import {
  registerAccount,
  loginAccount,
  getAuthenticatedAccount,
  AuthError
} from './auth.service';

import { authenticate } from './auth.middleware';

export const authRouter = Router();

// Helper function to handle validation errors
const handleValidationError = (res, error: ZodError) => {
  res.status(400).json({
    success: false,
    message: 'Validation failed.',
    errors: error.flatten().fieldErrors
  });
};

// Helper function to handle authentication errors
const handleAuthError = (res, error: AuthError) => {
  res.status(error.statusCode).json({
    success: false,
    message: error.message
  });
};

// Route handler for user registration
const register: RequestHandler = async (req, res) => {
  try {
    const validation = registerSchema.safeParse(req.body);

    if (!validation.success) {
      handleValidationError(res, validation.error);
      return;
    }

    const result = await registerAccount(validation.data);

    res.status(201).json({
      success: true,
      message: 'Account registered successfully.',
      data: result
    });
  } catch (error) {
    if (error instanceof AuthError) {
      handleAuthError(res, error);
      return;
    }

    res.status(500).json({
      success: false,
      message: 'Unable to register account.'
    });
  }
};

// Route handler for user login
const login: RequestHandler = async (req, res) => {
  try {
    const validation = loginSchema.safeParse(req.body);

    if (!validation.success) {
      handleValidationError(res, validation.error);
      return;
    }

    const result = await loginAccount(validation.data);

    res.status(200).json({
      success: true,
      message: 'Login successful.',
      data: result
    });
  } catch (error) {
    if (error instanceof AuthError) {
      handleAuthError(res, error);
      return;
    }

    res.status(500).json({
      success: false,
      message: 'Unable to log in.'
    });
  }
};

// Route handler for retrieving authenticated user details
const me: RequestHandler = async (req, res) => {
  try {
    if (!req.authUser) {
      res.status(401).json({
        success: false,
        message: 'Authentication is required.'
      });
      return;
    }

    const account = await getAuthenticatedAccount(req.authUser);

    if (!account) {
      res.status(404).json({
        success: false,
        message: 'Account not found.'
      });
      return;
    }

    res.status(200).json({
      success: true,
      data: account
    });
  } catch {
    res.status(500).json({
      success: false,
      message: 'Unable to retrieve account.'
    });
  }
};

// Define routes
authRouter.post('/register', register);
authRouter.post('/login', login);
authRouter.get('/me', authenticate, me);