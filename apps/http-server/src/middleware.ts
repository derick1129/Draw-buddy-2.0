import jwt from "jsonwebtoken";
import { JWT_SECRET } from "@repo/backend-common/config";
import { NextFunction, Request, Response } from "express";

interface AuthRequest extends Request {
    userId?: string
}

export function middleware (req: AuthRequest, res: Response, next: NextFunction) {
    const token = req.headers["authorization"];
    if (!token) {
        return res.status(403).json({
            message: "Unauthorized"
        });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET) as { userId: string };
        req.userId = decoded.userId;
        next();
    } catch (e) {
        return res.status(403).json({
            message: "Unauthorized"
        })
    }
}