# Secret Santa Backend

Flask + SQLite. Everyone signs up, admin runs the draw, each person sees only their own giftee.

## Run
```
pip install -r requirements.txt
python app.py              # http://localhost:5000
python test_app.py         # end-to-end tests
```
Env vars: `DB_PATH` (default santa.db), `MIN_PARTICIPANTS` (default 3, can't go lower), `PORT`.

## How it works
- First person to sign up becomes **admin**.
- Auth: login returns a random token. Send it as `Authorization: Bearer <token>`. Only a hash of the token is stored; passwords are hashed.
- Draw: everyone is shuffled into one circle, each person gives to the next. So nobody gets themselves and (with 3+ people) there are no A->B / B->A pairs.
- States: `open` -> `locked` (admin, optional) -> `drawn`. Signups only work while `open`.
- The draw endpoint never returns the pairings, not even to the admin. No endpoint lists them.

## Endpoints
| Method | Path | Who | Notes |
|---|---|---|---|
| POST | /auth/signup | anyone | `{name,email,password}`, only while open |
| POST | /auth/login | anyone | returns token |
| POST | /auth/logout | user | |
| GET | /participants | user | names + ids only |
| GET | /participant/:id | self only | own profile |
| PATCH | /participant/:id/wishlist | self only | `{wishlist}` |
| DELETE | /participant/:id | admin | before draw only |
| GET | /draw/status | user | state + counts |
| POST | /draw/lock | admin | manual close of signups |
| POST | /draw/run | admin | once only, needs >= MIN_PARTICIPANTS |
| GET | /my-giftee | user | your giftee's name + wishlist |
| GET | /my-wishlist-giver | user | confirms you have a Santa, no identity |

## Design note
`/my-wishlist-giver` in the brief says "who's assigned to you", but showing that would
reveal your Santa. So it only confirms you have one and shows the wishlist they see.
