from cryptography.hazmat.primitives.asymmetric import ec

# Resolve built-in "int" as a method parameter, in case of tuples
var_generic = 42
private_key, other_var = ec.generate_private_key(var_generic), "test" # Noncompliant {{42}}

# Resolve imported class as a method parameter, in case of tuples
other_var, private_key = "test", ec.generate_private_key(ec.SECP384R1()) # Noncompliant {{SECP384R1}}

# Resolve custom class "TestClass1" as a method parameter (this case will probably not happen in practice)
class TestClass1:
    class_var = 42
private_key = ec.generate_private_key(TestClass1()) # Noncompliant {{TestClass1}}

# Resolve imported class in intermediary variable as a method parameter
v1 = ec.SECP384R1()
private_key = ec.generate_private_key(v1) # Noncompliant {{SECP384R1}}

# Resolve imported class in function result as a method parameter
def func1():
    return ec.SECP384R1()
private_key = ec.generate_private_key(func1()) # Noncompliant {{SECP384R1}}

# Resolve imported class in function result as a method parameter, in case of tuples, with intermediary variable
def func2():
    return 42, ec.SECP384R1()
v2 = func2()[1]
private_key = ec.generate_private_key(v2) # Noncompliant {{SECP384R1}}

# Resolve conditional function result, by resolving all possible cases
def func7(bool):
    if (bool):
        res = ec.SECP384R1()
    else:
        res = ec.SECP192R1()
    return res
private_key = ec.generate_private_key(func7(True)) # Noncompliant {{SECP384R1}} {{SECP192R1}}

# Resolve conditional function result, by resolving all possible cases, in case of tuples
def func8(bool):
    if (bool):
        res = ec.SECP384R1()
    else:
        res = ec.SECP192R1()
    return "test", res
private_key = ec.generate_private_key(func8(False)[1]) # Noncompliant {{SECP384R1}} {{SECP192R1}}

# Resolve a tuple member
tup = (ec.SECP384R1(), ec.BrainpoolP256R1)
private_key = ec.generate_private_key(tup[1]) # Noncompliant {{BrainpoolP256R1}}

# Resolve a list member
l1 = [ec.SECP384R1(), ec.SECP192R1()]
private_key = ec.generate_private_key(l1[0]) # Noncompliant {{SECP384R1}}

# Resolve a list member, with intermediary variable
l2 = [ec.SECP384R1(), ec.SECP192R1()]
if True:
    v3 = l2
private_key = ec.generate_private_key(v3[1]) # Noncompliant {{SECP192R1}}

# Resolve built-in "list" as a method parameter
l3 = [ec.SECP384R1(), ec.SECP192R1()]
private_key = ec.generate_private_key(l3) # Noncompliant {{SECP192R1}} {{SECP384R1}}

# Resolve an empty built-in "list" as a method parameter
l4 = []
private_key = ec.generate_private_key(l4) # No finding!

# Resolve a dictionary member
dict1 = {
  "some_name": ec.SECP384R1(),
  "other_name": ec.BrainpoolP256R1(),
  "a_third_one": ec.SECP192R1()
}
private_key = ec.generate_private_key(dict1["other_name"]) # Noncompliant {{BrainpoolP256R1}}

# Resolve built-in "dict" as a method parameter
dict2 = {
  "some_name": ec.SECP384R1(),
  "other_name": ec.BrainpoolP256R1(),
  "a_third_one": ec.SECP192R1()
}
private_key = ec.generate_private_key(dict2) # Noncompliant {{BrainpoolP256R1}} {{SECP192R1}} {{SECP384R1}}

# Resolve a dictionary member that does not exist of a non-empty dictionnary (in this case we resolve all dictionnary members)
dict4 = {
  "some_name": ec.SECP384R1(),
  "other_name": ec.BrainpoolP256R1(),
  "a_third_one": ec.SECP192R1()
}
private_key = ec.generate_private_key(dict4["hello"]) # Noncompliant {{BrainpoolP256R1}} {{SECP192R1}} {{SECP384R1}}

# Resolve an empty built-in "dict" as a method parameter
dict5 = {}
private_key = ec.generate_private_key(dict5) # No finding!

# Resolve a dictionary member of an empty dictionnary: in this particular case, we resolve the name of the member, that carries more information than the name of the dictionnary. Because we have no type information, we resolve it with type ANY (which explains why we have several detections here, as this test example contains the same rule with different types)
# The detection {{24}} comes from the conversion of "abc" to an int due to one of the rule having `.shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BIT))`
dict3 = {}
private_key = ec.generate_private_key(dict3["abc"]) # Noncompliant {{24}} {{abc}} {{abc}} {{abc}} {{abc}} {{abc}}

# Resolve built-in "set" as a method parameter
set1 = {ec.SECP384R1(), ec.BrainpoolP256R1(), ec.SECP192R1()}
private_key = ec.generate_private_key(set1) # Noncompliant {{BrainpoolP256R1}} {{SECP192R1}} {{SECP384R1}}

# Resolve an empty built-in "set" as a method parameter
set2 = {}
private_key = ec.generate_private_key(set2) # No finding!
