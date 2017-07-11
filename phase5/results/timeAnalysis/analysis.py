def parse(filename):
    result = {}
    content = ""

    with open(filename, 'r') as f:
        content = f.readlines()

    for line in content:
        line = line.split(',')
        name = line[0].strip()
        time = float(line[1].strip())
        if result.get(name) == True:
            result[name] = (result[name][0] + time, result[name][1]+1)
        else:
            result[name] = (time, 1)

    for name in result.keys():
        result[name] = result[name][0]/result[name][1]
    return result



result_hw = parse('snake_hw.log')
result_sim = parse('snake_sim.log')
orig = parse('orig.log')

print(orig)
print(result_hw)
print(result_sim)
print("Function\tHW\tSIM\tORIG")
for name in result_hw.items():
    if name[0].strip() in orig:
        print('{0} \t {1:.6f} \t {2:.6f} \t {3:.6f}'.format(name[0], name[1], result_sim[name[0]], orig[name[0]]))
    else:
        print('{0} \t {1:.6f} \t {2:.6f}'.format(name[0],name[1], result_sim[name[0]]))
