from dataclasses import dataclass

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

@dataclass
class Point:
    """ An integer point (x,y) on a Curve """
    x: int
    y: int

    def add(self, other):
        """elliptic cruve addition
        """
        # handle special case of P + 0 = 0 + P = 0
        if self == INF:
            return other
        if other == INF:
            return self
        # handle special case of P + (-P) = 0
        if self.x == other.x and self.y != other.y:
            return INF
        if self.x == other.x:
            m = (3 * self.x**2) * pow(2 * self.y, -1, P)
        else:
            m = (self.y - other.y) * pow(self.x - other.x, -1, P)

        rx = (m**2 - self.x - other.x) % P
        ry = (-(m*(rx - self.x) + self.y)) % P

        return Point(rx, ry)

    def __mul__(self, k):
        """double and add - optimization for add G 
        to itself a very large number of times
        """
        assert isinstance(k, int) and k >= 0
        result = INF
        while k:
            if k % 2 == 1: 
                result = self.add(result)

            self = self.add(self)
            k >>= 1
        return result

INF = Point(None, None)