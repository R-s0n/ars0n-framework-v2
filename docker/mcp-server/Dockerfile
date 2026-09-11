FROM node:20-alpine

WORKDIR /app

# The lockfile has to be copied too, not just package.json. All four dependencies are caret-ranged,
# so `npm install` against package.json alone re-resolves them from the live registry on every
# rebuild and two images built from the same commit can differ. That matters most for
# @modelcontextprotocol/sdk: the SDK is the wire protocol this server speaks, and the lock pins it
# at 1.30.0 while the range ^1.12.1 would accept anything newer. npm ci installs the locked tree
# exactly and fails loudly if the two files ever drift apart.
#
# No --omit=dev here on purpose: package.json declares no devDependencies at all, so the flag would
# omit nothing. The lockfile's 140 entries are all runtime, none flagged dev.
COPY package.json package-lock.json ./
RUN npm ci

COPY src/ ./src/

EXPOSE 3001

CMD ["node", "src/index.js"]
