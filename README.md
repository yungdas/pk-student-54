# PK STUDENT

เว็บแอปติดตามงานค้างสำหรับห้อง 5/4 ออกแบบให้ใช้งานบนมือถือ มีระบบสะสมแต้ม แลกรางวัล ROV/เกมอื่น อีเวนต์ เช็กอินต่อเนื่อง โปรไฟล์ และหน้าจัดการสำหรับแอดมิน

## เริ่มใช้งาน

- เปิด `index.html` ผ่านเว็บเบราว์เซอร์
- โหมดเดโมเก็บข้อมูลไว้ในเบราว์เซอร์เครื่องนั้น
- ดูวิธีตั้งค่า Supabase และห้องออนไลน์ใน [SUPABASE_SETUP.md](SUPABASE_SETUP.md)

## ไฟล์สำคัญ

- `index.html` — เว็บแอปหลัก
- `assets/rov_game_logo.webp` — ภาพเกม ROV ที่ใช้ในหน้ารางวัล
- `supabase/schema.sql` — โครงสร้างฐานข้อมูลและ RPC สำหรับ Supabase
- `SUPABASE_SETUP.md` — วิธีตั้งค่าฐานข้อมูลและ deploy
- `pk_student_demo_v1.html`, `pk_student_v2_3_reference.html` — ไฟล์เดโม/ต้นแบบที่เก็บไว้ในโปรเจกต์

## ความปลอดภัย

ห้าม commit ไฟล์ `.env`, access token, `service_role` key หรือข้อมูลล็อกอินส่วนตัว ใช้เฉพาะ Supabase Publishable key/anon key ในหน้าเชื่อมต่อของเว็บ และเปิดใช้ RLS ตาม schema
