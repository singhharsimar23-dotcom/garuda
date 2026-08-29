import { createClient } from "@supabase/supabase-js"

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL || "https://sulnilwykmrosirbdvil.supabase.co"
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY || "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InN1bG5pbHd5a21yb3NpcmJkdmlsIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODc3OTQ4NDksImV4cCI6MjEwMzM3MDg0OX0.HMdCMiBUNWOv3PdF8LfLVu5O7ku4eciJElrximhDlAo"

export const supabase = createClient(supabaseUrl, supabaseAnonKey, {
  auth: {
    persistSession: false,
    autoRefreshToken: false,
    detectSessionInUrl: false,
  },
})
