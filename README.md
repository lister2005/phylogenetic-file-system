# PFS — the Phylogenetic File System

Most of us keep our work in a mess of copies: `report.docx`, `report_v2.docx`,
`report_FINAL.docx`, `report_FINAL_really.docx`. Each one is a full copy, none of
them knows about the others, and finding out what changed means opening two
files side by side and squinting.

PFS takes a different approach. It treats your files the way biologists treat
living things: as families with a history. Every save becomes a new
**generation** instead of overwriting the last one. Files remember where they
came from. Files that share a lot of content are recognised as relatives, even
if their names have nothing in common. And you can see all of it at once, as a
living map of your files.

## What you get

- **Nothing is overwritten.** Every save is kept. Go back to any earlier
  version of any file, whenever you like.
- **History that can branch.** Try a different direction from an older draft
  without losing your newer work, then bring the two branches back together.
  When both changed the same part, PFS asks you which to keep; it never
  guesses.
- **Files find their relatives.** PFS notices which files are alike, groups them
  into families, and can draw a family tree of how similar everything is.
- **Space-saving storage.** Files are cut into small pieces, and a piece that
  is already stored is never stored twice. In one test, 100 saved versions of a
  100 MB file took 468 MB instead of 10.5 GB.
- **Everything is encrypted.** Your vault (the folder where PFS keeps your
  files) is unreadable without your passphrase.
- **It repairs itself.** Spare copies of shared pieces (or of every piece, if
  you turn that on with `spares all`) let PFS recover from disk damage, and it
  tells you when it does.
- **Three ways in:**
  - a **desktop app** that draws your files as an animated map, with a time
    slider to look back at how things were;
  - a **command shell** for typing commands;
  - a **mounted folder**, so any other program can open and save files in PFS
    as if it were an ordinary folder.

  With the Python engine, all three can use the same vault at the same time.

## What to expect

PFS runs on **Linux**. It is a working system, not a mock-up, but it is also a
young project: some parts are polished, a few are still experimental. There
are two interchangeable storage engines, one written in Python and a faster one
in C++. A vault belongs to the engine that created it.

PFS doesn't replace your computer's own file system. It looks after the files
you put into a vault, and leaves everything else alone.

## Get started

You need Python 3.12. The C++ engine is optional and also needs `cmake`, `g++`,
`libssl-dev` and `libsqlite3-dev`.

```sh
python3 -m venv .venv
.venv/bin/python3 -m pip install -r requirements.txt

# optional: the C++ engine
cmake -S cpp_engine -B cpp_engine/build -DCMAKE_BUILD_TYPE=Release
cmake --build cpp_engine/build -j4
```

Run everything from this folder with `.venv/bin/python3`. Nothing needs `sudo`.

## Try it

Start with a practice vault, so your real files are never at risk:

```sh
.venv/bin/python3 pfs_gui.py ~/pfs_practice        # the desktop app
.venv/bin/python3 pfs_cli.py ~/pfs_practice        # the command shell
.venv/bin/python3 pfs_fuse.py mount ~/pfs_practice ~/pfs_mount   # a mounted folder
```

(For the mounted folder, create the empty folder `~/pfs_mount` first, and stop
it later with `.venv/bin/python3 pfs_fuse.py stop ~/pfs_practice`.)

The first time, PFS asks you to choose a passphrase. Don't lose it: there is no
way to recover a vault without it.

In the desktop app, click **New File(s)** and add a few files: a text file, a
photo and an edited copy of the photo. Watch the related ones drift together.
Edit the text file a couple of times, switch to the **Tree** view to see each
save as its own version, and drag the time slider at the bottom to look back.

In the shell, type `help` to see every command. A few to start with:

```text
pfs> write ~/Documents/report.txt report     store a file
pfs> list                                     see what's stored
pfs> lineage report                           its history
pfs> checkout report 0 ~/first_draft.txt      get an old version back
pfs> similar report                           find related files
```

To use the C++ engine instead, add `--engine cpp` to the app or the shell, and
mount with `mount_pfs_cpp.py`.

## Learn more

**[user_manual.pdf](user_manual.pdf)** explains the whole system in plain
language: the ideas behind it, how your files are stored and protected, every
part of the desktop app, the shell, what PFS can't do yet, and a guided first
walk through everything.
