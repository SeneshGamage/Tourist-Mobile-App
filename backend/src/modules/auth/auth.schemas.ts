import { z } from 'zod';

import { ACCOUNT_ROLES } from './auth.types';

// Helper function to validate fullName for specific roles
const validateFullName = (data: any, context: z.RefinementCtx) => {
  if ((data.role === 'TOURIST' || data.role === 'GUIDE') && !data.fullName) {
    context.addIssue({
      code: 'custom',
      path: ['fullName'],
      message: 'Full name is required for TOURIST and GUIDE roles.'
    });
  }
};

// Helper function to validate businessName for VRSP role
const validateBusinessName = (data: any, context: z.RefinementCtx) => {
  if (data.role === 'VRSP' && !data.businessName) {
    context.addIssue({
      code: 'custom',
      path: ['businessName'],
      message: 'Business name is required for VRSP role.'
    });
  }
};

// Schema for user registration
export const registerSchema = z
  .object({
    role: z.enum(ACCOUNT_ROLES), // Role must be one of the defined ACCOUNT_ROLES

    fullName: z.string().trim().min(2).max(150).optional(), // Full name (optional)

    businessName: z.string().trim().min(2).max(150).optional(), // Business name (optional)

    email: z.string().trim().email().max(255), // Valid email address

    password: z.string().min(8).max(100), // Password with a minimum of 8 characters

    phone: z.string().trim().min(7).max(20).optional() // Phone number (optional)
  })
  .superRefine((data: z.infer<typeof registerSchema>, context: z.RefinementCtx) => {
    // Validate fullName and businessName based on role
    validateFullName(data, context);
    validateBusinessName(data, context);
  });

// Schema for user login
export const loginSchema = z.object({
  role: z.enum(ACCOUNT_ROLES), // Role must be one of the defined ACCOUNT_ROLES

  email: z.string().trim().email().max(255), // Valid email address

  password: z.string().min(1).max(100) // Password with a minimum of 1 character
});

// Types for the schemas
export type RegisterInput = z.infer<typeof registerSchema>;
export type LoginInput = z.infer<typeof loginSchema>;