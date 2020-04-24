import inspect
import database
print(dir(database.Database))
      
def getStuff(method):
    db = database.Database

    args = inspect.getfullargspec(getattr(db, method))

    formattedArgs = ''
    annotations = args.annotations.copy()
    del annotations['return']

    for arg in annotations:
        formattedArgs += f"    '{arg}': {str(annotations[arg])[8:-2]},\n"
    md = f"### {method}\n```\n{{\n    'type': '{method}',\n{formattedArgs}}}\n```\n---\n\n"
    print(md)
    return md

file = ''

for member in inspect.getmembers(database.Database):
    if inspect.isfunction(member[1]) and not member[0].startswith('_'):
        file += getStuff(member[0])

with open('yay.md', 'w+') as f:
    f.write(file)
