# The Flag Is the Pattern — Official Writeup

## Overview

This challenge hides the message across multiple files.
No single file contains the flag.

Instead, the solution depends on:

- file metadata
- ordering
- selective reading

---

## Step 1: Inspect the Files

The provided directory contains several text files.
Opening any individual file reveals random-looking content.

Nothing obvious appears in isolation.

---

## Step 2: Observe File Sizes

Listing the directory with file sizes reveals that:

- each file has a unique size
- sizes increase consistently

This suggests ordering is important.

---

## Step 3: Sort by Size

Sort the files by size (ascending).

Examples:

**Linux / macOS**

```bash
ls -lS
```
