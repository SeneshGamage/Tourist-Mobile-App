
import { Router } from 'express';

import {
  register,
  login,
  me
} from './auth.controller';

import { authenticate } from './auth.middleware';

export const authRouter = Router();

authRouter.post('/register', register);

authRouter.post('/login', login);

authRouter.get('/me', authenticate, me);
