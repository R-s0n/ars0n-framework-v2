FROM node:18-alpine

WORKDIR /app

COPY package.json package-lock.json ./
# This should be `npm ci` so the build obeys the lockfile instead of re-resolving caret ranges, but
# it cannot be yet: package-lock.json is stale relative to package.json and npm ci refuses to run on
# a mismatch. Seven direct deps were added to package.json without the lock being regenerated
# (@tanstack/react-query, react-force-graph-2d, react-window, js-yaml and the three
# @testing-library packages), and js-yaml is worse than merely absent - the lock resolves it to the
# 3.14.1 copy pulled in transitively, which does not satisfy the ^4.1.0 the app asks for. Verified
# by running `npm ci` against copies of both files: it aborts with EUSAGE before installing
# anything. Regenerate the lockfile with `npm install` and commit it, then switch this to npm ci.
RUN npm install

COPY . .

RUN npm run build

# Pinned to the major that is actually in use: the current image has serve 14.2.6, read out of
# /usr/local/lib/node_modules/serve/package.json. This pin changes nothing today, because 14.2.6 is
# also the registry's current `latest` - the point is that unpinned, this line silently follows
# `latest` across a future major bump, and the `serve -s build` call below depends on that CLI
# staying the same. Kept at the major rather than 14.2.6 exactly so patch fixes still land.
RUN npm install -g serve@14

CMD ["serve", "-s", "build"]

EXPOSE 3000
