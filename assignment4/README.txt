CRYPTOGRAPHIC HASH FUNCTIONS ASSIGNMENT
CSC-321 Module 4 Assignment - Hashing and Passwords

===============================================================================
CONTENTS
===============================================================================

This package contains complete implementations for both tasks:

FILES:
1. task1_hash_collisions.py    - Full implementation of Task 1
2. task2_password_cracking.py  - Full implementation of Task 2
3. shadow.txt                  - Shadow file with bcrypt hashes
4. test_task1.py              - Quick test/demo of Task 1
5. test_task2.py              - Quick test/demo of Task 2
6. assignment_answers.txt      - Complete answers to all 4 questions
7. README.txt                  - This file

===============================================================================
TASK 1: EXPLORING PSEUDO-RANDOMNESS AND COLLISION RESISTANCE
===============================================================================

OBJECTIVE:
Investigate the pseudorandom and collision-resistant properties of SHA256.

COMPONENTS:
a) Hash arbitrary inputs with SHA256
b) Hash strings with Hamming distance of exactly 1 bit
c) Find collisions on truncated hashes (8-50 bits)

HOW TO RUN:
-----------
cd /home/claude
python3 task1_hash_collisions.py

EXPECTED OUTPUT:
- Console output showing:
  * SHA256 hashes of test inputs
  * Pairs of strings with Hamming distance 1 and their vastly different hashes
  * Collision results for 8, 10, 12, ..., 50 bit digests
  * Number of attempts and time for each collision

- Graph file: collision_analysis.png
  * Left plot: Digest Size vs Collision Time
  * Right plot: Digest Size vs Number of Inputs (with theoretical 2^(n/2) line)

RUNTIME:
- Small digests (8-20 bits): < 1 second each
- Medium digests (22-36 bits): 1-30 seconds each
- Large digests (38-46 bits): 30 seconds - 5 minutes each
- Largest digests (48-50 bits): 5-30 minutes each
- TOTAL: Approximately 30-60 minutes for complete run

QUICK TEST:
If you want to see results quickly without waiting:
python3 test_task1.py
(This runs only 8, 10, 12 bit collisions for demonstration)

===============================================================================
TASK 2: BREAKING REAL HASHES
===============================================================================

OBJECTIVE:
Crack bcrypt password hashes from a shadow file using dictionary attack.

SHADOW FILE FORMAT:
Username:$2b$WorkFactor$SaltHash

Example:
Bilbo:$2b$08$J9FW66ZdPI2nrIMcOxFYI.qx268uZn.ajhymLP/YHaAsfBGP3Fnmq
       └─┬┘ └┬┘ └────────┬────────┘└─────────┬─────────┘
      Algo  WF    Salt (22 chars)    Hash (31 chars)

USERS AND WORKFACTORS:
- Workfactor 8:  Bilbo, Gandalf, Thorin (3 users)
- Workfactor 9:  Fili, Kili (2 users)
- Workfactor 10: Balin, Dwalin, Oin (3 users)
- Workfactor 11: Gloin, Dori, Nori (3 users)
- Workfactor 12: Ori, Bifur, Bofur (3 users)
- Workfactor 13: Durin (1 user)

HOW TO RUN:
-----------
# Option 1: Sequential (simpler, recommended for assignment)
cd /home/claude
python3 task2_password_cracking.py

# Option 2: Parallel (faster - modify script to set use_parallel=True)
# Edit task2_password_cracking.py, line 171, change:
# task_2_main(shadow_file_path, use_parallel=True)

EXPECTED RUNTIME:
(Times are ESTIMATES - will vary based on CPU and word position in dictionary)

Sequential (Single Core):
- Workfactor 8:  ~1-2 hours per user
- Workfactor 9:  ~2-4 hours per user
- Workfactor 10: ~4-8 hours per user
- Workfactor 11: ~8-16 hours per user
- Workfactor 12: ~16-24 hours per user
- Workfactor 13: ~24-48 hours per user
TOTAL: ~150-200 hours (6-8 days)

Parallel (8 Cores):
TOTAL: ~20-30 hours (1-1.5 days)

IMPORTANT NOTES:
1. The assignment warns: "can take 17-18 hours of processing time"
2. You can crack lower workfactors first and submit partial results
3. Run overnight or over multiple days
4. The script saves progress and shows which passwords are cracked

OPTIMIZATION TIPS:
- Run on fastest available computer
- Close other applications to free CPU
- Consider running different workfactor groups separately
- Most common words appear early in dictionary, so some passwords crack quickly

QUICK TEST:
python3 test_task2.py
(This demonstrates bcrypt functionality and estimates timing)

===============================================================================
ASSIGNMENT QUESTIONS - ANSWERS PROVIDED
===============================================================================

All four questions have detailed answers in: assignment_answers.txt

QUESTION 1: Hamming distance observations and hash differences
- Answer explains avalanche effect
- Notes ~50% of hash bits change with 1-bit input change

QUESTION 2: Birthday bound and collision analysis
- Maximum hashes needed: 2^n + 1
- Expected hashes: 2^(n/2)
- Estimates for 256-bit: 10^25 years (infeasible)

QUESTION 3: Pre-image resistance on 8-bit digests
- Yes, can break one-way property
- Collisions are EASIER than pre-images (2^(n/2) vs 2^n)

QUESTION 4: Multi-word password cracking time estimates
- word1:word2: 240 years (single CPU)
- word1:word2:word3: 32 million years (single CPU)
- word1:word2:number: 24 million years (single CPU)
- Detailed analysis with parallel and GPU estimates provided

===============================================================================
REPORT STRUCTURE
===============================================================================

Your PDF report should include:

1. INTRODUCTION
   - Brief overview of assignment objectives
   - Team members list

2. TASK 1: EXPLORING PSEUDO-RANDOMNESS AND COLLISION RESISTANCE
   a) Code listing for SHA256 hashing
   b) Results showing hashes of arbitrary inputs
   c) Hamming distance results with hash comparisons
   d) Collision finding code
   e) Collision results table (bits, attempts, time)
   f) Two graphs: Time vs Bits, Inputs vs Bits
   
   Questions:
   - Q1: Hamming distance observations
   - Q2: Birthday bound analysis
   - Q3: Pre-image resistance discussion

3. TASK 2: BREAKING REAL HASHES
   a) Code listing for password cracking
   b) Results table showing all cracked passwords
   c) Timing data for each workfactor
   
   Question:
   - Q4: Multi-word password time estimates

4. CONCLUSIONS
   - Key observations
   - Security implications
   - Lessons learned

5. APPENDIX (if needed)
   - Full code listings
   - Additional graphs or data

===============================================================================
TIPS FOR SUCCESS
===============================================================================

1. START EARLY
   - Task 2 can take days to run
   - Don't wait until the last minute

2. RUN IN STAGES
   - Test with small bit sizes first (Task 1)
   - Crack low workfactors first (Task 2)
   - Submit partial results if time runs out

3. OPTIMIZE SMARTLY
   - Use parallel processing if you understand it
   - Run on fastest available computer
   - Consider cloud computing for Task 2

4. DOCUMENT EVERYTHING
   - Take screenshots of running programs
   - Save output logs
   - Record timing data as you go

5. UNDERSTAND THE CONCEPTS
   - Don't just run code - understand WHY
   - Explain the cryptographic principles
   - Connect results to theory

6. WRITE CLEARLY
   - Explain technical concepts clearly
   - Use graphs and tables effectively
   - Proofread for clarity

===============================================================================
TROUBLESHOOTING
===============================================================================

PROBLEM: "ModuleNotFoundError: No module named 'bcrypt'"
SOLUTION: pip install bcrypt --break-system-packages

PROBLEM: "ModuleNotFoundError: No module named 'nltk'"
SOLUTION: pip install nltk --break-system-packages

PROBLEM: Task 1 takes too long on large bit sizes
SOLUTION: Be patient - 50-bit can take 30+ minutes. Consider running overnight.

PROBLEM: Task 2 is taking forever
SOLUTION: This is expected! See runtime estimates above. Run in background.

PROBLEM: Python crashes or runs out of memory
SOLUTION: 
- Reduce bit size range in Task 1
- Process one user at a time in Task 2
- Restart Python and try again

PROBLEM: Can't find shadow.txt
SOLUTION: Update file path in task2_password_cracking.py line 164

===============================================================================
GRADING RUBRIC (100 POINTS)
===============================================================================

TASK 1 (45 points):
- Collision finding code: 10 points
- Hash calculations/graph: 10 points
- Question 1: 5 points
- Question 2: 5 points
- Question 3: 5 points

TASK 2 (40 points):
- Password cracking code: 10 points
- Workfactor 8-13 solutions: 30 points (5 points each)
- Question 4: 10 points

DEMONSTRATION (15 points):
- Live demo with all team members present: 15 points

===============================================================================
CONTACT INFORMATION
===============================================================================

If you have questions:
1. Check assignment instructions on Canvas
2. Review Professor Yocam's hints (included in uploaded documents)
3. Ask during office hours or via email

Good luck with your assignment!

===============================================================================