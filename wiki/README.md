# FilterDNS Wiki - Setup Instructions

This directory contains wiki pages for the FilterDNS Proxy GitHub repository.

## How to Push These Pages to GitHub Wiki

GitHub wikis are stored in a separate git repository. Follow these steps to set up and push these pages:

### 1. Enable Wiki on GitHub

1. Go to your GitHub repository
2. Click on "Settings"
3. Scroll down to "Features" section
4. Enable "Wikis" if not already enabled

### 2. Clone the Wiki Repository

GitHub creates a separate repository for wikis at `https://github.com/yourusername/filter-dns.wiki.git`

```bash
# Clone the wiki repository
git clone https://github.com/yourusername/filter-dns.wiki.git
cd filter-dns.wiki
```

If the wiki is empty, GitHub will create it when you push the first page.

### 3. Copy Wiki Pages

Copy all `.md` files from this `wiki/` directory to the cloned wiki repository:

```bash
# From the filter-dns repository root
cp wiki/*.md /path/to/filter-dns.wiki/
```

### 4. Commit and Push

```bash
cd /path/to/filter-dns.wiki
git add .
git commit -m "Add wiki pages"
git push origin master
```

### 5. Verify

Go to your GitHub repository and click on the "Wiki" tab. You should see all the pages.

## Wiki Page Structure

- **Home.md** - Main overview page
- **Installation.md** - Installation guide
- **Configuration.md** - Configuration reference
- **Use-Cases.md** - Usage scenarios
- **Architecture.md** - How FilterDNS works
- **Troubleshooting.md** - Common issues and solutions
- **FAQ.md** - Frequently asked questions
- **_Sidebar.md** - Wiki navigation sidebar

## Updating Wiki Pages

To update wiki pages:

1. Edit the `.md` files in this `wiki/` directory
2. Copy updated files to the cloned wiki repository
3. Commit and push changes

## Wiki Links

GitHub wikis support internal links using `[[PageName]]` syntax. All pages are linked using this format for easy navigation.

## Notes

- GitHub wikis use Markdown format
- The `_Sidebar.md` file controls the wiki navigation sidebar
- Page names are case-sensitive
- Use `[[PageName]]` for internal wiki links
