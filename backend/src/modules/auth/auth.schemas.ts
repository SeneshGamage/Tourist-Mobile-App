
import { z } from 'zod';
import { ACCOUNT_ROLES } from './auth.types';

const roleSchema = z.enum(ACCOUNT_ROLES);

export const registerSchema = z.object({
  role: roleSchema,

  fullName: z.string().trim().min(2).max(150).optional(),

  businessName: z.string().trim().min(2).max(150).optional(),

  email: z.string().trim().email().max(255),

  password: z.string().min(8).max(72),

  phone: z.string().trim().min(7).max(25).optional()
}).superRefine((data, ctx) => {
  if (
    (data.role === 'TOURIST' || data.role === 'GUIDE') &&
    !data.fullName
  ) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: 'Full name is required for this account role.',
      path: ['fullName']
    });
  }

  if (data.role === 'VRSP' && !data.businessName) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: 'Business name is required for VRSP registration.',
      path: ['businessName']
    });
  }
});

export const loginSchema = z.object({
  role: roleSchema,
  email: z.string().trim().email().max(255),
  password: z.string().min(1).max(72)
});

export type RegisterInput = z.infer<typeof registerSchema>;
export type LoginInput = z.infer<typeof loginSchema>;
