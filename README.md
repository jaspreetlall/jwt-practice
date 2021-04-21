# jwt-practice
Working demo for Building Blocks team for implementation.

Required environment variables

ACCESS_TOKEN_SECRET=
REFRESH_TOKEN_SECRET=

To generate these tokens for testing purposes
- Step 1 - open terminal
- Step 2 - run node
- Step 3 - require('crypto').randomBytes(64).toString('hex')
- Step 4 - select and copy (CTRL + SHFT + C) the resulting string and use as one token
- Step 5 - repeat step 3 to generate more strings as required
- Step 6 - to exit when done -> CTRL + C
