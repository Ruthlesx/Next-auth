import NextAuth from "next-auth/next";
import Credientals from "next-auth/providers/credentials";
import bcrypt from 'bcryptjs'
import User from "@/models/User";
import connectDB from "@/config/db";


export const authOptions = {
  providers: [
    CredientalsProvider({
      id: 'credientals',
      name: 'credientals',
      credentials: {
        email: {
          label: 'Email',
          type: 'text'
        },
        password: {
          label: 'Password',
          type: 'password'
        },
      },

      async authorize(credientals) {
        await connectDB();

        try {
          const user = await User.findOne({ email: credientals.email })

          if (user) {
            const isPasswordCorrect = await bcrypt.compare(
              credentials.password,
              user.password
            );

            if (isPasswordCorrect) {
              return user
            }
          }


        } catch (error) {
          throw new Error(error)
        }
      },
    }),
  ],

  callbacks: {
    async signIn({user, account}) {
      if (account?.provider == 'credientals') {
        return true
      }
    },
  },
}


export const handler = NextAuth(authOptions);
export { handler as GET, handler as POST }