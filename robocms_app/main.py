import asyncio
from routes import setup_routes
from aiohttp import web
from aiohttp_session import setup as setup_session
from aiohttp_session.redis_storage import RedisStorage
from aiohttp_security import setup as setup_security
from aiohttp_security import SessionIdentityPolicy
from aiopg.sa import create_engine
from aioredis import create_pool
from settings import config

from db_auth import DBAuthorizationPolicy
from handlers import Web

async def init(loop):
    redis_pool = await create_pool(('localhost', 6379))
    dbengine = await create_engine(user= config['postgres']['user'],
                                   password=config['postgres']['password'],
                                   database=config['postgres']['database'],
                                   host=config['postgres']['host'])

    app = web.Application()
    app.dbengine = dbengine
    setup_session(app, RedisStorage(redis_pool))
    setup_security(app,
                   SessionIdentityPolicy(),
                   DBAuthorizationPolicy(dbengine))
    web_handlers = Web()
    web_handlers.configure(app)

    handler = app.make_handler()
    srv = await loop.create_server(handler, '127.0.0.1', 8080)
    print('Server started at http://127.0.0.1:8080')


    return srv, app, handler

    # return app


async def finalize(srv, app, handler):
    sock = srv.sockets[0]
    app.loop.remove_reader(sock.fileno())
    sock.close()

    await handler.finish_connections(1.0)
    srv.close()
    await srv.wait_closed()
    await app.finish()


def main():
    loop = asyncio.get_event_loop()
    srv, app, handler = loop.run_until_complete(init(loop))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        loop.run_until_complete((finalize(srv, app, handler)))


if __name__ == '__main__':
    main()
