Step 1: (1 Person)
Static Analysis
Input / Static Analysis, the user uses the initial queries to run first static analysis results.

LLM Interaction (2 People)
2A. 
Next, we identify how to prompt the LLM correctly, giving some lines of code for example as additional context, and ask it to create harnesses to exploit subchains.

2B.
We then recieve the output and parse it into files. 

3. KLEE Verification
We run the harnesses through KLEE and get appropraite info from KLEE (FE Stack Traces and variable information)
If the output is incorrect, we go back to STEP 2 and give additional error context (Chain of Through)

If we are correct, parse output and save to file


