# PFS: the Phylogenetic File System

*What if files were treated like genes?*

By **Kudi Aye Lordlister**. Who did what, how AI tools were used, and whose
work PFS builds on are set out in [AUTHORSHIP.md](AUTHORSHIP.md).

**Code:** https://github.com/lister2005/phylogenetic-file-system
**Manual:** [user_manual.pdf](user_manual.pdf) (57 pages)

---

## The spark

The idea came while I was taking a bioinformatics course on MIT
OpenCourseWare, 7.91J *Foundations of Computational and Systems Biology*.
Most of it was about genetics: how to measure the distance between genes, and how methods such as
Neighbour-Joining and UPGMA rebuild a family tree of species from nothing but
their differences.

What struck me was how efficient these methods are. Evolution has had
billions of years to find good solutions, and biologists have learned to
read its record with algorithms that are fast and surprisingly simple. Then
the thought came: a gene is a piece of information that gets copied, changed
and passed on. So is a file. If these algorithms can tell how closely two
genes are related, could they tell how closely two files are related?

It was a stroke of luck. If I hadn't happened to think of files right at that
moment, as genes, the connection would probably have gone unnoticed.

## From an idea to a design

I started researching how this could work in practice. That is where I found
the tools the idea needed:

- **Content-defined chunking**, from the FastCDC paper, a way of cutting a
  file into pieces so that an edit changes only the pieces around it. Pieces
  of a file play the part of the sequences in a gene.
- **Jaccard distance**, a simple measure of how much two sets have in common.
  Applied to the sets of pieces in two files, it gives a "genetic distance"
  between files.

MIT OpenCourseWare's 9.40 *Introduction to Neural Computation* inspired the
idea further, and its algorithms courses, 6.046J *Design and Analysis of
Algorithms* and 6.851 *Advanced Data Structures*, helped me develop the
design.

Then came the realisation that changed the whole design. If files can be
grouped by what they contain and by where they came from, folders and file
extensions stop being necessary. Files can organise themselves, the way
species fall into families without anyone filing them. I searched for an
existing system that organised files this way and couldn't find a public
one, so I decided to build it.

## The inspiration

I believe nature has a lot to teach us. Over billions of years, evolution
has learned from its mistakes and kept what works. Our job is to learn from
it, and to copy its ways and designs into the systems we build. PFS is one
attempt at that.

## What PFS is

PFS stores files the way biologists describe living things: as families with
a history. Every save becomes a new generation instead of overwriting the
last one. A file can branch into alternative versions and merge back
together. Files that share content are recognised as relatives even when
their names and extensions have nothing in common, and the whole collection
can be explored as a live, animated map.

It is a working system on Linux, not a mock-up: encrypted, space-saving,
self-repairing storage with two interchangeable engines (Python and C++), a
desktop app, a command shell, and a mounted folder that any program can use.

| Biology | In PFS |
|---|---|
| A gene | A file |
| Gene sequences | The pieces a file is cut into |
| Genetic distance | Jaccard distance between two files' pieces |
| Common ancestor | The first saved version of a file |
| Speciation | A save that produces a new version |
| Mutation | The part of a file that changed between versions |
| Branch | A different line of edits from an older version |
| Clade | A group of files that share a lot of content |
| Lateral gene transfer | A new file made by combining two unrelated files (`graft`) |

## What it does

- **Nothing is overwritten.** Every save is kept, and any version can be
  rebuilt exactly.
- **History can branch and merge.** When two branches changed the same part
  of a file, the user chooses which to keep. PFS never guesses.
- **Files find their relatives.** PFS groups close relatives into clades and
  draws their family tree with Neighbour-Joining or UPGMA, the same methods
  biologists use for species.
- **No folders, no extensions.** A file's type is read from its content, and
  its place on the map comes from its relationships.
- **Space-saving storage.** Each piece is stored once. 100 saved versions of
  a 100 MB file took 468.1 MB instead of 10.49 GB as full copies.
- **Encrypted and self-repairing.** AES-256-GCM encryption under a
  passphrase, and spare copies that let PFS recover from disk damage.
- **Three ways in.** A desktop app with a Time Machine slider, a command
  shell with commands named after the biology (`fork`, `graft`, `prune`,
  `lineage`), and a mounted folder that ordinary programs can use.

## How it works

**Cutting files into pieces.** Following FastCDC, PFS slides a small window
along the file (a Gear hash) and cuts where the content matches a pattern,
giving pieces of 4 to 16 KB. Insert a paragraph and only the nearby pieces
change; the rest still match the old version and are shared.

**Storing each piece once.** Each piece is identified by its SHA-256 hash in
an index shared by the whole vault, so identical content is stored once,
whichever file it belongs to.

**History.** Every version keeps its own complete list of pieces, and a
history store records each version's parents. The first version is as quick
to rebuild as the latest, and every rebuilt file is checked against the
original's hash.

**Similarity.** Separately from history, PFS takes small fingerprints of each
file and computes Jaccard distances between them. A background worker keeps
the clades and the family tree up to date as files change. History (what
happened to one file) and similarity (how alike two files are now) are kept
as separate ideas, just as in biology a family tree of species is a
different thing from the life story of one animal.

**Two engines.** A Python engine came first; a C++ engine was added later
and does the same job. The desktop app and the shell can use either.

## Building it: problems and what they taught

PFS didn't work well the first time, or the second. These are the seven
problems that taught the most, roughly in the order they turned up.

### 1. Storing a large file was painfully slow

Early on, saving a 1.3 GB file took 109 seconds, about 11 MB a second. The
tempting move was to blame Python and start rewriting things in C. Instead,
the write was run under a profiler, a tool that reports where a program
spends its time, and the answer was surprising: a single line was using 77%
of it.

The chunker reads a file in large blocks of several megabytes and looks for
cut points inside them. Every time it found one, that line copied the
*entire* block into a fresh piece of memory, even though the chunker only
ever looked at the first 16 KB of it. With thousands of cuts per file, it
was copying gigabytes of data for nothing. Limiting the copy to the part
actually needed brought writing up to about 55 MB a second: a 1.5 GB file
then took 28.6 seconds. To make sure nothing else had changed, the pieces
produced before and after the fix were compared and found identical, byte
for byte.

That one line set the habit for the rest of the project: measure first, and
don't trust a guess about where the time goes.

### 2. Every save got slower than the last

Before writing the C++ engine, the Python version was profiled again, and
this turned up a problem that a faster language would not have fixed. Each
time a file was saved, the history store rewrote the *whole* history of the
vault to disk, every version of every file, just to add one new entry. The
more you saved, the slower saving became: over 6,000 saved versions, one
save went from 3.7 to 42 milliseconds, and it would have kept growing for as
long as the vault was used.

The fix was to change the file format so that each save adds one small
record to the end of the history file instead of rewriting it. The full
history is only rewritten for rare operations such as renaming a file.
After the change, saving stayed just as fast however long the history grew.

### 3. The desktop app froze with many files

The desktop app places files on the map with a small physics simulation:
every dot pushes every other dot away, so they don't pile up. With 30 files
that is under a thousand comparisons per frame. With 1,000 files it is
nearly half a million, and one frame took more than a second, so the app
became unusable.

The fix borrows a trick from video games. The map is divided into a grid of
cells, and each dot is only compared with dots in its own cell and the cells
next to it. Dots far apart barely affect each other anyway, so the picture
looks the same, but the work now grows in step with the number of files
instead of with its square.

### 4. Deleting one copy deleted both

PFS saves space by storing identical content once. Two files with exactly
the same content share a single "recipe", the list of pieces that rebuilds
the file. That sharing is what makes a duplicate cost nothing. But the
delete command removed the recipe without asking whether another file still
needed it. Delete one of two identical files, and the other became
unreadable too.

This was found while working on something else, reclaiming unused space.
The fix was reference counting: before a recipe is removed, PFS counts how
many files and saved versions still use it, and keeps it while the count is
above zero.

### 5. Space that never came back

After deleting every file and running `vacuum`, the command that reclaims
unused space, the vault still reported 495 pieces as "in use" and refused
to shrink. Each stored piece keeps a count of how many files use it, and
those counts were wrong. Saving a file whose content hadn't changed (which
editors do all the time when they autosave) still added one to the count of
each of its pieces, with nothing ever taking it away. The extra counts piled
up, and pieces nothing used could never be freed.

The fix had two parts. PFS now recognises a save with unchanged content and
leaves the counts alone. And `vacuum` no longer trusts the stored counts: it
recounts every piece from the actual history and corrects any that are
wrong, so vaults damaged before the fix repair themselves.

### 6. Two programs, one lost write

This one was found by testing PFS the way a brand-new user would meet it.
When two copies of the shell saved to the same vault at the same moment, one
file could silently disappear. Each program kept its own copy of the vault's
list of files in memory, saved its change, and wrote the whole list back, so
the second program to finish overwrote the first one's addition. Neither
program reported an error, which made it the most serious bug of the
project.

The first fix was simple and safe: a program that opens a vault locks it,
and a second program is turned away with a clear message. That stopped the
damage, but it also meant you couldn't have the desktop app and the shell
open on the same vault. So the locking was later redesigned. Now every
program can keep the vault open at once, but each change takes a short
exclusive lock, first reloads whatever the other programs have changed, then
writes. Only jobs that rewrite the whole vault, such as `vacuum`, still need
it to themselves. A test runs three programs saving at the same time and
checks that every file survives and reads back exactly.

### 7. The bug that wasn't in the data

During testing, editing a file in the desktop app seemed to do nothing: "I
don't see any new file." The storage was checked again and again, and it was
working the whole time. Every save really did create a new version. The
problem was the picture: the main Web view shows one dot per file, its
latest version, so a new version only updated a dot that was already there.

The fix didn't touch the storage at all. After an edit, the app now switches
to the Tree view, where every version is its own dot and the new one visibly
appears. It was a useful reminder that a system can be correct and still
feel broken if people can't see what it did.

### A known blind spot

One problem hasn't been fixed, and it is built into how content-defined
chunking works. PFS decides where to cut a file by looking at the last 64
bytes before each position. If those bytes match a certain pattern (roughly
a 1 in 8,000 chance at any position), it cuts there. In ordinary files the
bytes keep changing, so cut points appear naturally every few kilobytes, and
because they depend on the content, they move with it when you edit.

Text that repeats exactly breaks this. If a 47-character phrase is repeated
over and over, the chunker only ever sees the same 47 situations again and
again. If none of them happens to match the pattern, there are no natural
cut points anywhere in the file, and PFS falls back to cutting every 16 KB,
its maximum piece size. That is exactly the fixed-size cutting that
content-defined chunking exists to avoid: insert two bytes near the start and
every later cut shifts, so every piece looks new. In a test, inserting two
bytes near the start of ordinary data left 8 of its 9 pieces shared with
the original; the same insertion in repeated text left none of them shared.

Ordinary writing doesn't trigger this, even when it is repetitive, but long
identical runs (padding, silence in audio, repeated log lines) can. It is
listed in the manual as a known limitation.

## Where it stands

**Works today:** encrypted, deduplicating storage with full history,
branching, merging and grafting; similarity grouping; two engines; the
desktop app, the shell and the mounted folder.

**Partly there:** a Linux kernel module version of PFS's storage has been
written and compiles, but hasn't yet been loaded and tested on a real
machine.

**Known limits:** Linux only; merges are settled per piece, not per line;
text that repeats exactly deduplicates poorly (see above); no independent
security audit; one passphrase per vault.

## The bigger vision

PFS is the first step of a larger idea I couldn't build yet: a computer that
works the way a living body does. Code would have structure and meaning the
way proteins do, with instructions folding and acting like protein
molecules. The operating system would be the brain, the buses and data paths
would be the neurons, and the programming language itself would have
biological analogues for each of its parts. That is the future I am hoping
to work towards. PFS shows that one piece of it, files that behave like
genes, works in practice.

## Credits and references

- **FastCDC.** Wen Xia, Hong Jiang, Dan Feng, Lei Tian, Min Fu and Yukun
  Zhou, "FastCDC: a Fast and Efficient Content-Defined Chunking Approach for
  Data Deduplication", 2016 USENIX Annual Technical Conference. PFS's
  chunking engine is built from this paper.
- **rust-gearhash** by Sam Rijs and contributors
  (https://github.com/srijs/rust-gearhash): PFS's Gear hash table and
  hasher were ported from it.
- **fastcdc-go** (https://github.com/jotfs/fastcdc-go) and **fastcdc-rs** by
  Nathan Fiedler (https://github.com/nlfiedler/fastcdc-rs): FastCDC
  implementations studied while building the chunker.
- **Neighbour-Joining.** Naruya Saitou and Masatoshi Nei, "The
  neighbor-joining method: a new method for reconstructing phylogenetic
  trees", *Molecular Biology and Evolution*, 1987.
- **UPGMA.** Robert Sokal and Charles Michener, 1958.
- **Jaccard index.** Paul Jaccard, 1901.
- **MIT OpenCourseWare:** 7.91J *Foundations of Computational and Systems
  Biology*, 6.046J / 18.410J *Design and Analysis of Algorithms*, 6.851
  *Advanced Data Structures* and 9.40 *Introduction to Neural Computation*.
- **Software PFS builds on:** Python, PySide6 (Qt), the `cryptography`
  library, NetworkX, fusepy and libfuse, SQLite, and OpenSSL.

## How it was made

My role, the use of AI tools, and the credits for others' work are set out
in [AUTHORSHIP.md](AUTHORSHIP.md).

## What I learned

**How an operating system handles files.** Building PFS took me below the
level where most programs work. I learned how a Linux kernel module is
built: how the kernel hands file operations such as open, read, write and
release to a driver, and why a mistake there can bring down the whole
machine rather than one program. I also learned how a mounted folder (FUSE)
lets ordinary programs use a storage system that isn't a real disk.

**Hashing.** I learned how a rolling hash (the Gear hash) can find cut
points in a file from its content alone, so that an edit shifts only the
pieces around it, and how a cryptographic hash (SHA-256) gives every piece a
fingerprint that changes completely if a single bit changes. Together they
let PFS store each piece only once.

**Cryptography.** I learned how encryption fits together in a real system: a
passphrase turned into a key with a deliberately slow function (scrypt),
data keys that are themselves encrypted and can be rotated, AES-256-GCM
encryption that also detects tampering, and blinded lookups that stop
someone holding the vault from checking whether it contains a known file.

**Memory and storage optimisation.** I learned to measure before
optimising. I learned to read large files in a stream instead of loading
them whole, to read only the parts of a file a program asks for, and how choices such as chunk size
trade storage savings against speed.

**File operations and shell scripting.** I learned how to write files
safely, so that a crash never leaves half a file (write to a temporary file,
then rename it), how to let several programs share one vault with file
locks, and how to drive and test a system from the command line.

**Working on a large project.** PFS grew to over 20,000 lines of
Python, C++ and C. I learned to keep two engines behaving the same,
to test every feature before calling it done, and to write down honestly
what the system can't do yet.
