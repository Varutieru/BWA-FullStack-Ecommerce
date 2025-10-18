import { Lucia } from "lucia";
import { PrismaAdapter } from "@lucia-auth/adapter-prisma";
import { RoleUser, PrismaClient } from "@prisma/client";
import prisma from "./prisma";

// Create adapter with type assertion
const adapter = new PrismaAdapter(
    (prisma as any).session,
    (prisma as any).user
);

export const lucia = new Lucia(adapter, {
    sessionCookie: {
        expires: false,
        attributes: {
            secure: process.env.NODE_ENV === "production"
        }
    },
    getUserAttributes: (attributes) => {
        return {
            id: attributes.id,
            name: attributes.name,
            email: attributes.email,
            role: attributes.role,
        };
    }
});

declare module "lucia" {
    interface Register {
        Lucia: typeof lucia;
        UserId: number;
        DatabaseUserAttributes: {
            id: number;
            name: string;
            email: string;
            role: RoleUser;
        };
    }
}