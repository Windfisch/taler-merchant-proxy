# taler-merchant-proxy

This is a reverse proxy for the GNU Taler merchant backend. It provides access to only the
order management endpoints, and requires a *different* access token than the actual merchant
backend. When the client-supplied access token is correct, it replaces the access token with
the actual backend's access token and forwards the request to there.

This allows to have public(ish) point-of-sale sites create new orders and check for their "paid"
status, without having to expose full merchant backend access to anyone who can read JSON.

It is meant to be used together with [taler-pos](https://github.com/SpitfireX/taler-pos).

## Usage

Edit the `proxy.py` file and set up the two token dictionaries at the top of the file.

Launch the proxy using `python3 proxy.py --hostname real-merchant-backend.example.org --port 8889`.

Use your favorite HTTP reverse proxy to have a subdomain's `/` location point to port 8889.

## Security considerations

In itself, this quality piece of python should bear no security issues by itself. However, in
its intended use case where the client token is kinda-publicly-known (but the real backend's token
is not), an attacker (i.e., everyone), can do the following:

- Create new orders
- Delete orders if they can guess the order id
- Check for an order's status if they can guess the order id

They can not:

- List all orders
- Change your merchant settings, like the payment method
- Do anything else. (This includes proper payment flow using a wallet. Use the real backend for that)
