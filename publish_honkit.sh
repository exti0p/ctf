# checkout to the master branch
git checkout -b gh-pages

# pull the latest updates
git reset --hard main

# build honkit
npm install
npm audit fix
npx honkit build

# copy the static site files into the current directory.
cp -R _book/* .

# remove 'node_modules' and '_book' directory
git clean -fx node_modules
git clean -fx _book

# add all files
git add .

# commit
git commit -am "Publish site"

# push to the origin
git push origin gh-pages --force

# checkout to the master branch
git checkout main
