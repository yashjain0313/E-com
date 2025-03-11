import { prisma } from "../server";
import { Request,Response } from "express";
import bcrypt from 'bcryptjs'
import jwt from "jsonwebtoken";
import {v4 as uuidv4 } from "uuid"

function generateToken (userId:string,email:string,role :string)
{
    const accessToken = jwt.sign({
        userId,
        email,
        role,
    },process.env.JWT_SECRET!,{expiresIn : "60m"});

    const refreshToken =uuidv4()
    return {accessToken,refreshToken}
}

async function setTokens(res:Response ,accessToken:string,refreshToken:string) {
    res.cookie('accessToken',accessToken,{
        httpOnly :true,
        secure:process.env.NODE_ENV ==='production',
        sameSite:"strict",
        maxAge : 60*60*1000
    })
    
    res.cookie('refreshToken',refreshToken,{
        httpOnly :true,
        secure:process.env.NODE_ENV ==='production',
        sameSite:"strict",
        maxAge : 7*24*60*60*1000
    })
}

//Register the user and check if old user 
//create user

export const register = async(req: Request, res: Response) : Promise<void> =>{
    try{
        const {name,email,password }=req.body
        const existingUser = await prisma.user.findUnique({
            where :{email}
        })

        if(existingUser)
        {
            res.status(400).json({
                success :false,
                error:"user with the email exists"
            })
            return
        }
        const hashedPassword= await bcrypt.hash(password,12)
        const user = await prisma.user.create({
         data :  { name:name,
            email:email,
            password:hashedPassword,
        role:"USER"
    }
        })
        res.status(201).json({
            message : "User Registered Successfully",
            success : true,
            userId : user.id
        })
        
    }catch(error)
    {
        console.error(error);
        res.status(500).json({error : "Registrationn Failed"})
        
    }
}


//LOGIn

export const login = async (req : Request,res:Response) : Promise <void> =>{
    try{
    const {email,password}=req.body
    const extractCurrentUser = await prisma.user.findUnique({
        where:{email}
    })
    if(!extractCurrentUser || !(await bcrypt.compare(password,extractCurrentUser.password)))
    {     res.status(401).json({
          success : false,
            error : "Invaild Credentials",
        })
        return
    }

//create our access and refresh token
const {accessToken,refreshToken} =generateToken(extractCurrentUser.id,
    extractCurrentUser.email,
    extractCurrentUser.role);

    //setTokens
    await setTokens(res,accessToken,refreshToken)
    res.status(201).json({
        success:true,
        message:'Login Successfully',
        user:{
            id:extractCurrentUser.id,
            name:extractCurrentUser.name,
            email:extractCurrentUser.email,
            role : extractCurrentUser.role
        }
    })

}catch(error)
{
    console.error(error);
    res.status(500).json({error : "Login Failed"})
    
}
}


//LogOUT
export const refreshAccessToken =async (req : Request,res:Response) : Promise <void> =>{

const refreshToken=req.cookies.refreshToken;
if(!refreshToken)
{
    res.status(401).json({
        success:false,
        error:"Invalid Refresh Token"
    })
}


try{
    const user = await prisma.user.findFirst({
        where:{
            refreshToken :refreshToken
        }
    })
    if(!user)
    {
        res.status(401).json({
            success:false,
            error:"User Not Found"
        })
        return;
    }
    const {accessToken, refreshToken: newRefreshToken} = generateToken(user.id, user.email, user.role)
    await setTokens(res,accessToken,newRefreshToken)
    res.status(201).json({
        success:true,
        message:"Refresh token Refreshed Successfully"
    })

}
catch(error)
{
    console.error(error);
    res.status(500).json({
        error:"Refresh Token Error"
    })
    
}
}



export const logout =async (req : Request,res:Response) : Promise <void> =>{

    res.clearCookie('accessToken')
    res.clearCookie('refreshToken')

    res.json({
        success:true,
        message:"User Logged out successfully"
    })

}