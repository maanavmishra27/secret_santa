import os, tempfile
os.environ["DB_PATH"] = tempfile.mktemp(suffix=".db")
from app import app

c = app.test_client()
def signup(n): return c.post("/auth/signup", json={"name": n, "email": f"{n}@x.com", "password": "password123"})
def login(n): return {"Authorization": "Bearer " + c.post("/auth/login", json={"email": f"{n}@x.com", "password": "password123"}).json["token"]}

names = ["a", "b", "c", "d", "e", "f"]
for n in names: assert signup(n).status_code == 201
assert signup("a").status_code == 409
h = {n: login(n) for n in names}

assert c.get("/participants").status_code == 401
assert c.post("/draw/run", headers=h["b"]).status_code == 403          # non-admin
assert c.get("/participant/1", headers=h["b"]).status_code == 403      # not own profile
assert c.patch("/participant/2/wishlist", headers=h["b"], json={"wishlist": "socks"}).status_code == 200
assert c.get("/my-giftee", headers=h["a"]).status_code == 409          # before draw
assert c.delete("/participant/6", headers=h["a"]).status_code == 200   # admin delete pre-draw
names.remove("f")

assert c.post("/draw/run", headers=h["a"]).status_code == 200
assert c.post("/draw/run", headers=h["a"]).status_code == 409          # only once
assert signup("late").status_code == 403                               # locked
assert c.delete("/participant/2", headers=h["a"]).status_code == 409

ids = {n: i + 1 for i, n in enumerate(names)}
pairs = {}
for n in names:
    r = c.get("/my-giftee", headers=h[n]).json["giftee"]
    pairs[ids[n]] = r["id"]
assert all(g != r for g, r in pairs.items())                           # never self
assert all(pairs[r] != g for g, r in pairs.items())                    # no mutual
assert sorted(pairs.values()) == sorted(pairs.keys())                  # everyone gifted once
print("wishlist visible to gifter:", [c.get("/my-giftee", headers=h[n]).json["giftee"]["wishlist"] for n in names])
assert c.post("/auth/logout", headers=h["a"]).status_code == 200
assert c.get("/my-giftee", headers=h["a"]).status_code == 401
print("ALL TESTS PASSED")
