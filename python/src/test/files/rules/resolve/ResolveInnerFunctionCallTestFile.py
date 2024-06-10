from cryptography.hazmat.primitives.asymmetric import ec

# Resolve function result that does not depend on a parameter
def fun1():
    return ec.SECP384R1()
private_key = ec.generate_private_key(fun1()) # Noncompliant {{SECP384R1}}

# Resolve function result which was given an imported class as method parameter
def fun2(arg):
    return arg
private_key = ec.generate_private_key(fun2(ec.SECP384R1())) # Noncompliant {{SECP384R1}}

# Resolve function result which was given an imported class as one of its two method parameters
def algorithm(alg, version) :
    return alg
def test1() :
    temp = algorithm(ec.SECP384R1(), 1.3)
    private_key = ec.generate_private_key(temp) # Noncompliant {{SECP384R1}}

# More complicated example mixing several functions and resolution challenges
def func3() :
    return 42, ec.SECP384R1()
def func4(arg4) :
    res4 = arg4
    return res4, "hello"
def func5() :
    res51 = func3()[1]
    res52 = func4(res51)[0]
    return ec.generate_private_key(res52) # Noncompliant {{SECP384R1}}

# Resolve argument in the case of multiple consecutive calls to the same function
def func6(arg) :
    temp = arg
    return temp
def func7() :
    some_var = ec.SECP384R1()
    res = func6(func6(some_var))
    return ec.generate_private_key(res) # Noncompliant {{SECP384R1}}

# Resolve when using a function with multiple parameters as argument
def multi(a1, a2):
    return a2, a1
def func8():
    temp = multi(ec.SECP384R1(), ec.BrainpoolP256R1())
    return ec.generate_private_key(temp) # Noncompliant {{SECP384R1}} {{BrainpoolP256R1}}
def func8():
    temp = multi(ec.SECP384R1(), ec.BrainpoolP256R1())
    return ec.generate_private_key(temp[0]) # Noncompliant {{BrainpoolP256R1}}

# In the case of a class declaration, it will only resolve the name of the class
class Parent():
    pass
class Child(Parent):
    pass
def func9():
    parent = Parent()
    child = Child(parent)
    return ec.generate_private_key(child) # Noncompliant {{Child}}
