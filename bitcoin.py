import lib
from dataclasses import dataclass

# Bitcoin constants
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

@dataclass
class Point:
    x: int
    y: int

    def __add__(self, other):
        raise NotImplemented

    def __mul__(self, k):
        x = str(self.x).encode()
        y = str(self.y).encode()
        k = str(k).encode()
        x, y = lib.ecc_mul(x, y, k)
        return Point(int.from_bytes(x, 'little'), int.from_bytes(y, 'little'))


# A point on the bitcoin curve
G = Point(
    x = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    y = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
)

print("Generator is on the curve: ", (G.y**2 - G.x**3 - 7) % P == 0)

print(G * 3)

