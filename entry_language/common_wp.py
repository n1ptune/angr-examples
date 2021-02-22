src = ["Dufhbmf", "pG`imos", "ewUglpt"]
flag=''
print(chr(ord(src[0][1])-1))
for i in range(12):
    flag+=chr(ord(src[i%3][2*(i//3)])-1)
print(flag)
