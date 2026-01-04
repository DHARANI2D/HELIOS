/** @type {import('tailwindcss').Config} */
export default {
    content: [
        "./index.html",
        "./src/**/*.{js,ts,jsx,tsx}",
    ],
    theme: {
        extend: {
            colors: {
                aegis: {
                    primary: '#0F172A',
                    secondary: '#1E293B',
                    accent: '#3B82F6',
                    danger: '#EF4444',
                    success: '#10B981',
                    warning: '#F59E0B'
                }
            },
            backdropBlur: {
                xs: '2px',
            }
        },
    },
    plugins: [],
}
