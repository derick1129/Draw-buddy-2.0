import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { CreateRoomSchema, CreateUserSchema, SigninSchema } from "@repo/common/types";
import { prismaClient } from "@repo/db/client";
import { JWT_SECRET } from "@repo/backend-common/config"

const app = express();
app.use(express.json());
 

app.post("/signup", async (req, res) => {
    const parsedData = CreateUserSchema.safeParse(req.body);
    if (!parsedData.success) {
        res.status(403).json({
            message: "Invalid inputs"
        });
        return;
    }
    try {
        const hashedPassword = await bcrypt.hash(parsedData.data.password, 5);
        const user = await prismaClient.user.create({
            data: {
                email: parsedData.data.email,
                password: hashedPassword,
                name: parsedData.data.name
            }
        })
        return res.status(201).json({
            userId: user.id
        });
    } catch (e) {
        return res.status(403).json({
            message: "User with this email already exists"
        })
    }
});

app.post("/signin", async (req, res) => {
    const parsedData = SigninSchema.safeParse(req.body);
    if (!parsedData.success) {
        res.status(403).json({
            message: "Invalid inputs"
        });
        return;
    }

    try {
        const user = await prismaClient.user.findFirst({
            where: {
                email: parsedData.data.email
            }
        });

        if (!user) {
            return res.status(403).json({
                message: "user not found"
            })
        }

        const passwordMatched = await bcrypt.compare(
            parsedData.data.password,
            user.password
        );
        if (!passwordMatched) {
            return res.status(403).json({
                message: "Incorrect credentials"
            });
        }

        const token = jwt.sign({
            userId: user.id
        }, JWT_SECRET)

        return res.json({
            token
        });
    } catch (e) {
        return res.status(500).json({
            messsage: "something went wrong"
        })
    }
});

app.post("/room", async (req, res) => {
    const parsedData = CreateRoomSchema.safeParse(req.body);
    if (!parsedData.success) {
        return res.status(403).json({
            message: "Invalid inputs"
        });
    }

    try {
        const room = await prismaClient.room.create({
            data: {
                slug: parsedData.data.name,
                //@ts-ignore
                adminId: req.userId
            }
        })
        return res.json({
            roomId: room.id
        })
    } catch (e) {
        return res.status(411).json({
            message: "Room already exists"
        })
    }
});

app.listen(3001);