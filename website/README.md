# DESAS Website

## Deployment Instructions

### Option 1: Netlify Drop (Easiest)
1. Go to https://app.netlify.com/drop
2. Drag the entire `website` folder
3. Get your live URL instantly!

### Option 2: Netlify CLI
```bash
cd website
npx netlify-cli deploy --prod
```

### Option 3: GitHub + Netlify
1. Push website folder to GitHub
2. Connect repository to Netlify
3. Auto-deploy on every push

## Features

- ✅ Modern minimalist white theme
- ✅ Custom CSS animation showing email analysis workflow
- ✅ Fixed navigation header with smooth scroll
- ✅ Fully responsive design
- ✅ Cross-platform download options
- ✅ Application screenshots gallery
- ✅ No external dependencies (except Font Awesome icons)

## Animation Concept

The hero animation visualizes the DESAS workflow:
1. **Email** (blue) - Suspicious email arrives
2. **Shield** (green) - Enters isolated sandbox
3. **Particles** (blue/purple) - Analysis in progress
4. **Report** (purple) - Forensic PDF generated

## Download Links

Before deploying, update the download links in `index.html`:

- Line ~796: Windows Installer
- Line ~807: Windows Portable  
- Line ~818: macOS DMG
- Line ~829: Linux AppImage

Replace `#` with your Google Drive direct download links.

## Browser Support

- Chrome/Edge: ✅ Full support
- Firefox: ✅ Full support
- Safari: ✅ Full support
- Mobile: ✅ Responsive design
