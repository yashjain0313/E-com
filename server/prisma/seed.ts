import { PrismaClient } from "@prisma/client";
import bcrypt from 'bcryptjs'

const prisma= new PrismaClient()

async function main() {
    const email = "godyash@gmail.com";
    const password = "12345678";
    const name = "Super Admin";

    const existingSuperAdmin = await prisma.user.findFirst({
        where : {role:"SUPER_ADMIN" }
    })
    if (existingSuperAdmin){return}

    const hashedPassword =  await bcrypt.hash(password,10)
    const superAdminUser = await prisma.user.create({
        data:{
            email,
            name,
            password:hashedPassword,
            role: "SUPER_ADMIN"
        }
    })

    console.log("Super admin created Successfully ",superAdminUser.email)
}


main().catch((e)=>{
    console.error(e);
    process.exit(1);
    
}).finally(async()=>{
    await prisma.$disconnect();
});