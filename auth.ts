import NextAuth from 'next-auth';
import { authConfig } from './auth.config';

import { sql } from '@vercel/postgres';
import type { User } from '@/app/lib/definitions';
import Credentials from 'next-auth/providers/credentials';
import { z } from 'zod';
import bcrypt from 'bcrypt';
import { AuthError } from 'next-auth';

async function getUser(email: string): Promise<User | undefined> {
  try {
    const user = await sql<User>`SELECT * FROM users WHERE email=${email}`;
    return user.rows[0];
  } catch (error) {
    console.error('Failed to fetch user:', error);
    throw new Error('Failed to fetch user.');
  }
}

export const { auth, signIn, signOut } = NextAuth({
  ...authConfig,
  providers: [
    Credentials({
      async authorize(credentials) {
        console.log('> 1');
        const parsedCredentials = z
          .object({ email: z.string().email(), password: z.string().min(6) })
          .safeParse(credentials);

        console.log('> 2');

        if (parsedCredentials.success) {
          try {
            console.log('> 3');

            const { email, password } = parsedCredentials.data;
            const user = await getUser(email);

            console.log('> 3.1');

            if (!user) {
              throw new Error('User not found');
            }

            console.log('> 3.2');

            const passwordsMatch = await bcrypt.compare(password, user.password);

            if (passwordsMatch) return user;
          } catch (e) {
            console.log('> 4');

            if (e instanceof Error) {
              console.error('Failed to fetch user:', e.message);
            }

            return null;
          }
        }
        console.log('> 5');
        console.log('Invalid credentials');
        return null;
      },
    }),
  ],
});
