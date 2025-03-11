# Authentication Controller Explanation

This document explains the authentication controller code in detail for beginners to understand how user registration, login, token management, and logout functionality work in a Node.js Express application.

## Overview

The authentication controller (`authController.ts`) handles user authentication processes including:
- User registration
- User login
- Access token refresh
- User logout

The code uses modern web technologies and security practices:
- **TypeScript**: A typed superset of JavaScript for better code quality
- **Prisma**: An ORM (Object-Relational Mapper) for database operations
- **Express**: A web framework for handling HTTP requests
- **JWT (JSON Web Tokens)**: For secure authentication
- **bcrypt**: For password hashing
- **HTTP cookies**: For storing authentication tokens securely

## Imports Explained

```typescript
import { prisma } from "../server";
```
This imports the Prisma client instance that was configured elsewhere in the application. Prisma is used to interact with your database.

```typescript
import { Request, Response } from "express";
```
These are TypeScript types from the Express framework. `Request` represents an incoming HTTP request, and `Response` is used to send back HTTP responses.

```typescript
import bcrypt from 'bcryptjs'
```
bcrypt is a library for hashing passwords. Password hashing is essential for security - instead of storing actual passwords, we store a scrambled version that can't be reversed.

```typescript
import jwt from "jsonwebtoken";
```
JSON Web Tokens (JWT) are used to create secure tokens that can identify users after they've logged in.

```typescript
import {v4 as uuidv4 } from "uuid"
```
This imports the v4 function from the uuid library, which generates random unique identifiers (used for refresh tokens).

## Helper Functions

### generateToken Function

```typescript
function generateToken(userId: string, email: string, role: string) {
    const accessToken = jwt.sign({
        userId,
        email,
        role,
    }, process.env.JWT_SECRET!, {expiresIn: "60m"});

    const refreshToken = uuidv4()
    return {accessToken, refreshToken}
}
```

This function creates two important security tokens:

1. **accessToken**:
   - Created using JWT
   - Contains user information (userId, email, role) in an encoded format
   - Signed with a secret key (JWT_SECRET from environment variables)
   - Set to expire in 60 minutes (1 hour)
   - Used for authenticating API requests

2. **refreshToken**:
   - A random UUID (Universally Unique Identifier)
   - Used to get a new access token when the current one expires
   - More secure because it's just a random string with no encoded information

### setTokens Function

```typescript
async function setTokens(res: Response, accessToken: string, refreshToken: string) {
    res.cookie('accessToken', accessToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: "strict",
        maxAge: 60 * 60 * 1000
    })
    
    res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: "strict",
        maxAge: 7 * 24 * 60 * 60 * 1000
    })
}
```

This function sets both tokens as HTTP cookies in the user's browser:

- **httpOnly: true** - Prevents JavaScript access to cookies (security against XSS attacks)
- **secure** - Only sends cookies over HTTPS in production mode
- **sameSite: "strict"** - Prevents the cookie from being sent in cross-site requests (security against CSRF attacks)
- **maxAge** - Sets how long cookies last:
  - Access token: 60 minutes (60 * 60 * 1000 milliseconds)
  - Refresh token: 7 days (7 * 24 * 60 * 60 * 1000 milliseconds)

## Main Authentication Functions

### register Function

```typescript
export const register = async(req: Request, res: Response): Promise<void> => {
    try {
        const {name, email, password} = req.body
        const existingUser = await prisma.user.findUnique({
            where: {email}
        })

        if(existingUser) {
            res.status(400).json({
                success: false,
                error: "user with the email exists"
            })
            return
        }
        const hashedPassword = await bcrypt.hash(password, 12)
        const user = await prisma.user.create({
            data: {
                name: name,
                email: email,
                password: hashedPassword,
                role: "USER"
            }
        })
        res.status(201).json({
            message: "User Registered Successfully",
            success: true,
            userId: user.id
        })
        
    } catch(error) {
        console.error(error);
        res.status(500).json({error: "Registration Failed"})
    }
}
```

This function handles new user registration:

1. Extracts name, email, and password from the request body
2. Checks if a user with the same email already exists
3. If the user exists, returns a 400 error
4. If not, hashes the password for security (with bcrypt using 12 rounds of salting)
5. Creates a new user in the database with:
   - The provided name and email
   - The hashed password (never store plain passwords!)
   - A default role of "USER"
6. Returns a success message with HTTP status 201 (Created)
7. Handles any errors that might occur during this process

### login Function

```typescript
export const login = async (req: Request, res: Response): Promise<void> => {
    try {
        const {email, password} = req.body
        const extractCurrentUser = await prisma.user.findUnique({
            where: {email}
        })
        if(!extractCurrentUser || !(await bcrypt.compare(password, extractCurrentUser.password))) {
            res.status(401).json({
                success: false,
                error: "Invalid Credentials",
            })
            return
        }

        // Create access and refresh token
        const {accessToken, refreshToken} = generateToken(
            extractCurrentUser.id,
            extractCurrentUser.email,
            extractCurrentUser.role
        );

        // Set tokens
        await setTokens(res, accessToken, refreshToken)
        res.status(201).json({
            success: true,
            message: 'Login Successfully',
            user: {
                id: extractCurrentUser.id,
                name: extractCurrentUser.name,
                email: extractCurrentUser.email,
                role: extractCurrentUser.role
            }
        })
    } catch(error) {
        console.error(error);
        res.status(500).json({error: "Login Failed"})
    }
}
```

This function handles user login:

1. Gets email and password from request body
2. Looks up the user in the database by email
3. If user doesn't exist OR the password doesn't match:
   - Uses bcrypt.compare to check the password against the stored hash
   - Returns a 401 Unauthorized error with "Invalid Credentials" message
4. If credentials are valid:
   - Generates access and refresh tokens
   - Sets these tokens as secure HTTP cookies
   - Returns user information (excluding password) with a success message
5. Handles any errors that might occur

### refreshAccessToken Function

```typescript
export const refreshAccessToken = async (req: Request, res: Response): Promise<void> => {
    const refreshToken = req.cookies.refreshToken;
    if(!refreshToken) {
        res.status(401).json({
            success: false,
            error: "Invalid Refresh Token"
        })
    }

    try {
        const user = await prisma.user.findFirst({
            where: {
                refreshToken: refreshToken
            }
        })
        if(!user) {
            res.status(401).json({
                success: false,
                error: "User Not Found"
            })
            return;
        }
        const {accessToken, refreshToken: newRefreshToken} = generateToken(user.id, user.email, user.role)
        await setTokens(res, accessToken, newRefreshToken)
        res.status(201).json({
            success: true,
            message: "Refresh token Refreshed Successfully"
        })
    } catch(error) {
        console.error(error);
        res.status(500).json({
            error: "Refresh Token Error"
        })
    }
}
```

This function handles token refreshing when an access token expires:

1. Extracts the refresh token from cookies
2. If no refresh token exists, returns a 401 Unauthorized error
3. Finds a user with the matching refresh token in the database
4. If no user is found, returns a 401 Unauthorized error
5. If user is found:
   - Generates new access token and refresh token
   - Sets these new tokens as cookies
   - Returns success message
6. Handles any errors that might occur

### logout Function

```typescript
export const logout = async (req: Request, res: Response): Promise<void> => {
    res.clearCookie('accessToken')
    res.clearCookie('refreshToken')

    res.json({
        success: true,
        message: "User Logged out successfully"
    })
}
```

This function handles user logout:

1. Clears both the access token and refresh token cookies from the browser
2. Returns a success message

## Security Considerations in this Code

1. **Password Security**:
   - Passwords are hashed using bcrypt before storage
   - Original passwords are never stored in the database

2. **Token Security**:
   - Uses short-lived access tokens (1 hour)
   - Uses refresh tokens for getting new access tokens
   - Stores tokens in httpOnly cookies (not accessible via JavaScript)

3. **Cookie Protection**:
   - HttpOnly flag prevents JavaScript access
   - Secure flag ensures HTTPS-only in production
   - SameSite policy protects against cross-site request forgery

4. **Error Handling**:
   - Generic error messages to users
   - Detailed errors logged server-side only
   - Proper HTTP status codes used

## Potential Improvements

1. Add email verification during registration
2. Implement rate limiting for login attempts
3. Add two-factor authentication option
4. Store refresh tokens in the database with expiry dates
5. Implement a token blacklist for revoked tokens

## Conclusion

This authentication controller provides a secure way to manage user authentication with modern security practices. It handles the full lifecycle of authentication from registration and login through to token refresh and logout.
