const { ipcRenderer, clipboard } = require("electron"),
  moment = require("moment"),
  snekfetch = require("snekfetch"),
  Popper = require("@popperjs/core"),
  EventEmitter = require("events"),
  { setTimeout } = require("timers"),
  net = require("net"),
  Sortable = require("sortablejs"),
  Swal = require("sweetalert2"),
  fs = require("fs"),
  deepmerge = require("deepmerge");

class Collection extends Map {
  filter(fn) {
    const results = new Collection();
    for (const [key, val] of this) {
      if (fn(val, key, this)) results.set(key, val);
    }
    return results;
  }

  forEach(fn) {
    let i = 0;
    for (const [key, val] of this) fn(val, key, i++, this);
  }

  map(fn) {
    const array = new Array();
    let i = 0;
    for (const [key, val] of this) array[i++] = fn(val, key, i, this);
    return array;
  }

  mapValues(fn) {
    const coll = new Collection();
    let i = 0;
    for (const [key, val] of this) coll.set(key, fn(val, key, i, this));
    return coll;
  }

  array() {
    return [...this.values()];
  }

  keyArray() {
    return [...this.keys()];
  }

  every(fn) {
    for (const [key, val] of this) {
      if (!fn(val, key, this)) return false;
    }
    return true;
  }

  some(fn) {
    for (const [key, val] of this) {
      if (fn(val, key, this)) return true;
    }
    return false;
  }

  find(fn) {
    for (const [key, val] of this) {
      if (fn(val, key, this)) return val;
    }
  }

  findKey(fn) {
    for (const [key, val] of this) {
      if (fn(val, key, this)) return key;
    }
  }

  slice(start, end) {
    return new Collection([...this.entries()].slice(start, end));
  }

  first() {
    return this.values().next().value;
  }

  firstKey() {
    return this.keys().next().value;
  }

  last() {
    return this.array()[this.size - 1];
  }

  reduce(fn, initialValue) {
    let accumulator;
    if (typeof initialValue !== "undefined") {
      accumulator = initialValue;
      for (const [key, val] of this)
        accumulator = fn(accumulator, val, key, this);
    } else {
      let first = true;
      for (const [key, val] of this) {
        if (first) {
          accumulator = val;
          first = false;
          continue;
        }
        accumulator = fn(accumulator, val, key, this);
      }
    }
    return accumulator;
  }

  merge(...maps) {
    for (const map of maps) {
      for (const [key, val] of map) this.set(key, val);
    }
  }

  sort(compareFunction = (x, y) => +(x > y) || +(x === y) - 1) {
    return new Collection(
      [...this.entries()].sort((a, b) =>
        compareFunction(a[1], b[1], a[0], b[0])
      )
    );
  }
}

function RPCClient() {
  function keyMirror(arr) {
    return arr.reduce((acc, e) => {
      acc[e] = e;
      return acc;
    }, {});
  }

  function getPid() {
    return process.pid;
  }

  function uuid() {
    let uuid = "";
    for (let i = 0; i < 32; i++) {
      if (i === 8 || i === 12 || i === 16 || i === 20) {
        uuid += "-";
      }
      let n;
      if (i === 12) {
        n = 4;
      } else {
        const random = (Math.random() * 16) | 0;
        if (i === 16) {
          n = (random & 3) | 0;
        } else {
          n = random;
        }
      }
      uuid += n.toString(16);
    }
    return uuid;
  }

  function getIPCPath(id) {
    if (process.platform === "win32") {
      return `\\\\?\\pipe\\discord-ipc-${id}`;
    }
    const {
      env: { XDG_RUNTIME_DIR, TMPDIR, TMP, TEMP },
    } = process;
    const prefix = XDG_RUNTIME_DIR || TMPDIR || TMP || TEMP || "/tmp";
    return `${prefix.replace(/\/$/, "")}/discord-ipc-${id}`;
  }

  function getIPC(id = 0) {
    return new Promise((resolve, reject) => {
      const path = getIPCPath(id);
      const onerror = () => {
        if (id < 10) {
          resolve(getIPC(id + 1));
        } else {
          reject(new Error("Could not connect"));
        }
      };
      const sock = net.createConnection(path, () => {
        sock.removeListener("error", onerror);
        resolve(sock);
      });
      sock.once("error", onerror);
    });
  }

  function encode(op, data) {
    data = JSON.stringify(data);
    const len = Buffer.byteLength(data);
    const packet = Buffer.alloc(8 + len);
    packet.writeInt32LE(op, 0);
    packet.writeInt32LE(len, 4);
    packet.write(data, 8, len);
    return packet;
  }

  function decode(socket, callback) {
    const packet = socket.read();
    if (!packet) {
      return;
    }

    let { op } = working;
    let raw;
    if (working.full === "") {
      op = working.op = packet.readInt32LE(0);
      const len = packet.readInt32LE(4);
      raw = packet.slice(8, len + 8);
    } else {
      raw = packet.toString();
    }

    try {
      const data = JSON.parse(working.full + raw);
      callback({ op, data });
      working.full = "";
      working.op = undefined;
    } catch (err) {
      working.full += raw;
    }

    decode(socket, callback);
  }

  function subKey(event, args) {
    return `${event}${JSON.stringify(args)}`;
  }

  const RPCCommands = keyMirror([
    "DISPATCH",
    "AUTHORIZE",
    "AUTHENTICATE",
    "GET_GUILD",
    "GET_GUILDS",
    "GET_CHANNEL",
    "GET_CHANNELS",
    "GET_RELATIONSHIPS",
    "GET_USER",
    "SUBSCRIBE",
    "UNSUBSCRIBE",
    "SET_USER_VOICE_SETTINGS",
    "SET_USER_VOICE_SETTINGS_2",
    "SELECT_VOICE_CHANNEL",
    "GET_SELECTED_VOICE_CHANNEL",
    "SELECT_TEXT_CHANNEL",
    "GET_VOICE_SETTINGS",
    "SET_VOICE_SETTINGS_2",
    "SET_VOICE_SETTINGS",
    "CAPTURE_SHORTCUT",
    "SET_ACTIVITY",
    "SEND_ACTIVITY_JOIN_INVITE",
    "CLOSE_ACTIVITY_JOIN_REQUEST",
    "ACTIVITY_INVITE_USER",
    "ACCEPT_ACTIVITY_INVITE",
    "INVITE_BROWSER",
    "DEEP_LINK",
    "CONNECTIONS_CALLBACK",
    "BRAINTREE_POPUP_BRIDGE_CALLBACK",
    "GIFT_CODE_BROWSER",
    "OVERLAY",
    "BROWSER_HANDOFF",
    "SET_CERTIFIED_DEVICES",
    "GET_IMAGE",
    "CREATE_LOBBY",
    "UPDATE_LOBBY",
    "DELETE_LOBBY",
    "UPDATE_LOBBY_MEMBER",
    "CONNECT_TO_LOBBY",
    "DISCONNECT_FROM_LOBBY",
    "SEND_TO_LOBBY",
    "SEARCH_LOBBIES",
    "CONNECT_TO_LOBBY_VOICE",
    "DISCONNECT_FROM_LOBBY_VOICE",
    "SET_OVERLAY_LOCKED",
    "OPEN_OVERLAY_ACTIVITY_INVITE",
    "OPEN_OVERLAY_GUILD_INVITE",
    "OPEN_OVERLAY_VOICE_SETTINGS",
    "VALIDATE_APPLICATION",
    "GET_ENTITLEMENT_TICKET",
    "GET_APPLICATION_TICKET",
    "START_PURCHASE",
    "GET_SKUS",
    "GET_ENTITLEMENTS",
    "GET_NETWORKING_CONFIG",
    "NETWORKING_SYSTEM_METRICS",
    "NETWORKING_PEER_METRICS",
    "NETWORKING_CREATE_TOKEN",
    "SET_USER_ACHIEVEMENT",
    "GET_USER_ACHIEVEMENTS",
  ]);

  const RPCEvents = keyMirror([
    "CURRENT_USER_UPDATE",
    "GUILD_STATUS",
    "GUILD_CREATE",
    "CHANNEL_CREATE",
    "RELATIONSHIP_UPDATE",
    "VOICE_CHANNEL_SELECT",
    "VOICE_STATE_CREATE",
    "VOICE_STATE_DELETE",
    "VOICE_STATE_UPDATE",
    "VOICE_SETTINGS_UPDATE",
    "VOICE_SETTINGS_UPDATE_2",
    "VOICE_CONNECTION_STATUS",
    "SPEAKING_START",
    "SPEAKING_STOP",
    "GAME_JOIN",
    "GAME_SPECTATE",
    "ACTIVITY_JOIN",
    "ACTIVITY_JOIN_REQUEST",
    "ACTIVITY_SPECTATE",
    "ACTIVITY_INVITE",
    "NOTIFICATION_CREATE",
    "MESSAGE_CREATE",
    "MESSAGE_UPDATE",
    "MESSAGE_DELETE",
    "LOBBY_DELETE",
    "LOBBY_UPDATE",
    "LOBBY_MEMBER_CONNECT",
    "LOBBY_MEMBER_DISCONNECT",
    "LOBBY_MEMBER_UPDATE",
    "LOBBY_MESSAGE",
    "CAPTURE_SHORTCUT_CHANGE",
    "OVERLAY",
    "OVERLAY_UPDATE",
    "ENTITLEMENT_CREATE",
    "ENTITLEMENT_DELETE",
    "USER_ACHIEVEMENT_UPDATE",
    "READY",
    "ERROR",
  ]);

  const OPCodes = {
    HANDSHAKE: 0,
    FRAME: 1,
    CLOSE: 2,
    PING: 3,
    PONG: 4,
  };

  const working = {
    full: "",
    op: undefined,
  };

  class IPCTransport extends EventEmitter {
    constructor(client) {
      super();
      this.client = client;
      this.socket = null;
    }

    async connect() {
      let socket;
      try {
        socket = this.socket = await getIPC();
      } catch (e) {
        return Promise.reject(e);
      }
      socket.on("close", this.onClose.bind(this));
      socket.on("error", this.onClose.bind(this));
      this.emit("open");
      socket.write(
        encode(OPCodes.HANDSHAKE, {
          v: 1,
          client_id: this.client.clientId,
        })
      );
      socket.pause();
      socket.on("readable", () => {
        decode(socket, ({ op, data }) => {
          switch (op) {
            case OPCodes.PING:
              this.send(data, OPCodes.PONG);
              break;
            case OPCodes.FRAME:
              if (!data) {
                return;
              }
              this.emit("message", data);
              break;
            case OPCodes.CLOSE:
              this.emit("close", data);
              break;
          }
        });
      });
    }

    onClose(e) {
      this.emit("close", e);
    }

    send(data, op = OPCodes.FRAME) {
      this.socket.write(encode(op, data));
    }

    close() {
      this.send({}, OPCodes.CLOSE);
      this.socket.end();
    }

    ping() {
      this.send(uuid(), OPCodes.PING);
    }
  }

  class RPCClient extends EventEmitter {
    /**
     * @param {RPCClientOptions} [options] Options for the client.
     * You must provide a transport
     */
    constructor(options = {}) {
      super();

      this.options = options;

      this.accessToken = null;
      this.clientId = null;

      /**
       * Application used in this client
       * @type {?ClientApplication}
       */
      this.application = null;

      /**
       * User used in this application
       * @type {?User}
       */
      this.user = null;

      const Transport = IPCTransport;

      this.fetch = (method, path, { data, query } = {}) =>
        fetch(
          `${this.fetch.endpoint}${path}${query ? new URLSearchParams(query) : ""
          }`,
          {
            method,
            body: data,
            headers: {
              Authorization: `Bearer ${this.accessToken}`,
            },
          }
        ).then((r) => r.json());

      this.fetch.endpoint = "https://discordapp.com/api";

      /**
       * Raw transport userd
       * @type {RPCTransport}
       * @private
       */
      this.transport = new Transport(this);
      this.transport.on("message", this._onRpcMessage.bind(this));

      /**
       * Map of nonces being expected from the transport
       * @type {Map}
       * @private
       */
      this._expecting = new Map();

      /**
       * Map of current subscriptions
       * @type {Map}
       * @private
       */
      this._subscriptions = new Map();

      this._connectPromise = undefined;
      this.connected = false;
    }

    /**
     * Search and connect to RPC
     */
    connect(clientId) {
      if (this._connectPromise) {
        return this._connectPromise;
      }
      this._connectPromise = new Promise((resolve, reject) => {
        this.clientId = clientId;
        const timeout = setTimeout(
          () => reject(new Error("RPC_CONNECTION_TIMEOUT")),
          10e3
        );
        timeout.unref();
        this.once("connected", () => {
          clearTimeout(timeout);
          this.connected = true;
          resolve(this);
        });
        this.transport.once("close", () => {
          this._expecting.forEach((e) => {
            e.reject(new Error("connection closed"));
          });
          this.emit("disconnected");
          this.connected = false;
          this._connectPromise = undefined;
          reject();
        });
        this.transport.connect().catch(reject);
      });
      return this._connectPromise;
    }

    /**
     * @typedef {RPCLoginOptions}
     * @param {string} clientId Client ID
     * @param {string} [clientSecret] Client secret
     * @param {string} [accessToken] Access token
     * @param {string} [rpcToken] RPC token
     * @param {string} [tokenEndpoint] Token endpoint
     * @param {string[]} [scopes] Scopes to authorize with
     */

    /**
     * Performs authentication flow. Automatically calls Client#connect if needed.
     * @param {RPCLoginOptions} options Options for authentication.
     * At least one property must be provided to perform login.
     * @example client.login({ clientId: '1234567', clientSecret: 'abcdef123' });
     * @returns {Promise<RPCClient>}
     */
    async login(options = {}) {
      let { clientId, accessToken } = options;
      await this.connect(clientId);
      if (!options.scopes) {
        this.emit("ready");
        return this;
      }
      if (!accessToken) {
        accessToken = await this.authorize(options);
      }
      return this.authenticate(accessToken);
    }

    /**
     * Request
     * @param {string} cmd Command
     * @param {Object} [args={}] Arguments
     * @param {string} [evt] Event
     * @returns {Promise}
     * @private
     */
    request(cmd, args, evt) {
      return new Promise((resolve, reject) => {
        const nonce = uuid();
        this.transport.send({ cmd, args, evt, nonce });
        this._expecting.set(nonce, { resolve, reject });
      });
    }

    /**
     * Message handler
     * @param {Object} message message
     * @private
     */
    _onRpcMessage(message) {
      if (
        message.cmd === RPCCommands.DISPATCH &&
        message.evt === RPCEvents.READY
      ) {
        if (message.data.user) {
          this.user = message.data.user;
        }
        this.emit("connected");
      } else if (this._expecting.has(message.nonce)) {
        const { resolve, reject } = this._expecting.get(message.nonce);
        if (message.evt === "ERROR") {
          const e = new Error(message.data.message);
          e.code = message.data.code;
          e.data = message.data;
          reject(e);
        } else {
          resolve(message.data);
        }
        this._expecting.delete(message.nonce);
      } else {
        const subid = subKey(message.evt, message.args);
        if (!this._subscriptions.has(subid)) {
          return;
        }
        this._subscriptions.get(subid)(message.data);
      }
    }

    /**
     * Authorize
     * @param {Object} options options
     * @returns {Promise}
     * @private
     */
    async authorize({ scopes, clientSecret, rpcToken, redirectUri } = {}) {
      if (clientSecret && rpcToken === true) {
        const body = await this.fetch("POST", "/oauth2/token/rpc", {
          data: new URLSearchParams({
            client_id: this.clientId,
            client_secret: clientSecret,
          }),
        });
        rpcToken = body.rpc_token;
      }

      const { code } = await this.request("AUTHORIZE", {
        scopes,
        client_id: this.clientId,
        rpc_token: rpcToken,
      });

      const response = await this.fetch("POST", "/oauth2/token", {
        data: new URLSearchParams({
          client_id: this.clientId,
          client_secret: clientSecret,
          code,
          grant_type: "authorization_code",
          redirect_uri: "http://127.0.0.1",
        }),
      });

      return response.access_token;
    }

    /**
     * Authenticate
     * @param {string} accessToken access token
     * @returns {Promise}
     * @private
     */
    authenticate(accessToken) {
      return this.request("AUTHENTICATE", { access_token: accessToken }).then(
        ({ application, user }) => {
          this.accessToken = accessToken;
          this.application = application;
          this.user = user;
          this.emit("ready");
          return this;
        }
      );
    }

    /**
     * Fetch a guild
     * @param {Snowflake} id Guild ID
     * @param {number} [timeout] Timeout request
     * @returns {Promise<Guild>}
     */
    getGuild(id, timeout) {
      return this.request(RPCCommands.GET_GUILD, { guild_id: id, timeout });
    }

    /**
     * Fetch all guilds
     * @param {number} [timeout] Timeout request
     * @returns {Promise<Collection<Snowflake, Guild>>}
     */
    getGuilds(timeout) {
      return this.request(RPCCommands.GET_GUILDS, { timeout });
    }

    /**
     * Get a channel
     * @param {Snowflake} id Channel ID
     * @param {number} [timeout] Timeout request
     * @returns {Promise<Channel>}
     */
    getChannel(id, timeout) {
      return this.request(RPCCommands.GET_CHANNEL, { channel_id: id, timeout });
    }

    /**
     * Get all channels
     * @param {Snowflake} [id] Guild ID
     * @param {number} [timeout] Timeout request
     * @returns {Promise<Collection<Snowflake, Channel>>}
     */
    async getChannels(id, timeout) {
      const { channels } = await this.request(RPCCommands.GET_CHANNELS, {
        timeout,
        guild_id: id,
      });
      return channels;
    }

    /**
     * @typedef {CertifiedDevice}
     * @prop {string} type One of `AUDIO_INPUT`, `AUDIO_OUTPUT`, `VIDEO_INPUT`
     * @prop {string} uuid This device's Windows UUID
     * @prop {object} vendor Vendor information
     * @prop {string} vendor.name Vendor's name
     * @prop {string} vendor.url Vendor's url
     * @prop {object} model Model information
     * @prop {string} model.name Model's name
     * @prop {string} model.url Model's url
     * @prop {string[]} related Array of related product's Windows UUIDs
     * @prop {boolean} echoCancellation If the device has echo cancellation
     * @prop {boolean} noiseSuppression If the device has noise suppression
     * @prop {boolean} automaticGainControl If the device has automatic gain control
     * @prop {boolean} hardwareMute If the device has a hardware mute
     */

    /**
     * Tell discord which devices are certified
     * @param {CertifiedDevice[]} devices Certified devices to send to discord
     * @returns {Promise}
     */
    setCertifiedDevices(devices) {
      return this.request(RPCCommands.SET_CERTIFIED_DEVICES, {
        devices: devices.map((d) => ({
          type: d.type,
          id: d.uuid,
          vendor: d.vendor,
          model: d.model,
          related: d.related,
          echo_cancellation: d.echoCancellation,
          noise_suppression: d.noiseSuppression,
          automatic_gain_control: d.automaticGainControl,
          hardware_mute: d.hardwareMute,
        })),
      });
    }

    /**
     * @typedef {UserVoiceSettings}
     * @prop {Snowflake} id ID of the user these settings apply to
     * @prop {?Object} [pan] Pan settings, an object with `left` and `right` set between
     * 0.0 and 1.0, inclusive
     * @prop {?number} [volume=100] The volume
     * @prop {bool} [mute] If the user is muted
     */

    /**
     * Set the voice settings for a uer, by id
     * @param {Snowflake} id ID of the user to set
     * @param {UserVoiceSettings} settings Settings
     * @returns {Promise}
     */
    setUserVoiceSettings(id, settings) {
      return this.request(RPCCommands.SET_USER_VOICE_SETTINGS, {
        user_id: id,
        pan: settings.pan,
        mute: settings.mute,
        volume: settings.volume,
      });
    }

    /**
     * Move the user to a voice channel
     * @param {Snowflake} id ID of the voice channel
     * @param {Object} [options] Options
     * @param {number} [options.timeout] Timeout for the command
     * @param {boolean} [options.force] Force this move. This should only be done if you
     * have explicit permission from the user.
     * @returns {Promise}
     */
    selectVoiceChannel(id, { timeout, force = false } = {}) {
      return this.request(RPCCommands.SELECT_VOICE_CHANNEL, {
        channel_id: id,
        timeout,
        force,
      });
    }

    /**
     * Move the user to a text channel
     * @param {Snowflake} id ID of the voice channel
     * @param {Object} [options] Options
     * @param {number} [options.timeout] Timeout for the command
     * @param {boolean} [options.force] Force this move. This should only be done if you
     * have explicit permission from the user.
     * @returns {Promise}
     */
    selectTextChannel(id, { timeout, force = false } = {}) {
      return this.request(RPCCommands.SELECT_TEXT_CHANNEL, {
        channel_id: id,
        timeout,
        force,
      });
    }

    /**
     * Get current voice settings
     * @returns {Promise}
     */
    getVoiceSettings() {
      return this.request(RPCCommands.GET_VOICE_SETTINGS).then((s) => ({
        automaticGainControl: s.automatic_gain_control,
        echoCancellation: s.echo_cancellation,
        noiseSuppression: s.noise_suppression,
        qos: s.qos,
        silenceWarning: s.silence_warning,
        deaf: s.deaf,
        mute: s.mute,
        input: {
          availableDevices: s.input.available_devices,
          device: s.input.device_id,
          volume: s.input.volume,
        },
        output: {
          availableDevices: s.output.available_devices,
          device: s.output.device_id,
          volume: s.output.volume,
        },
        mode: {
          type: s.mode.type,
          autoThreshold: s.mode.auto_threshold,
          threshold: s.mode.threshold,
          shortcut: s.mode.shortcut,
          delay: s.mode.delay,
        },
      }));
    }

    /**
     * Get the voice channel the user is currently in. Returns null if the user is not connected to a voice channel.
     * @returns {Promise}
     */
    getSelectedVoiceChannel() {
      return this.request(RPCCommands.GET_SELECTED_VOICE_CHANNEL);
    }

    /**
     * Set current voice settings, overriding the current settings until this session disconnects.
     * This also locks the settings for any other rpc sessions which may be connected.
     * @param {Object} args Settings
     * @returns {Promise}
     */
    setVoiceSettings(args) {
      return this.request(RPCCommands.SET_VOICE_SETTINGS, {
        automatic_gain_control: args.automaticGainControl,
        echo_cancellation: args.echoCancellation,
        noise_suppression: args.noiseSuppression,
        qos: args.qos,
        silence_warning: args.silenceWarning,
        deaf: args.deaf,
        mute: args.mute,
        input: args.input
          ? {
            device_id: args.input.device,
            volume: args.input.volume,
          }
          : undefined,
        output: args.output
          ? {
            device_id: args.output.device,
            volume: args.output.volume,
          }
          : undefined,
        mode: args.mode
          ? {
            mode: args.mode.type,
            auto_threshold: args.mode.autoThreshold,
            threshold: args.mode.threshold,
            shortcut: args.mode.shortcut,
            delay: args.mode.delay,
          }
          : undefined,
      });
    }

    /**
     * Capture a shortcut using the client
     * The callback takes (key, stop) where `stop` is a function that will stop capturing.
     * This `stop` function must be called before disconnecting or else the user will have
     * to restart their client.
     * @param {Function} callback Callback handling keys
     * @returns {Promise<Function>}
     */
    captureShortcut(callback) {
      const subid = subKey(RPCEvents.CAPTURE_SHORTCUT_CHANGE);
      const stop = () => {
        this._subscriptions.delete(subid);
        return this.request(RPCCommands.CAPTURE_SHORTCUT, { action: "STOP" });
      };
      this._subscriptions.set(subid, ({ shortcut }) => {
        callback(shortcut, stop);
      });
      return this.request(RPCCommands.CAPTURE_SHORTCUT, {
        action: "START",
      }).then(() => stop);
    }

    /**
     * Sets the presence for the logged in user.
     * @param {object} args The rich presence to pass.
     * @param {number} [pid] The application's process ID. Defaults to the executing process' PID.
     * @returns {Promise}
     */
    setActivity(args = {}, pid = getPid()) {
      let timestamps;
      let assets;
      let party;
      let secrets;
      if (args.startTimestamp || args.endTimestamp) {
        timestamps = {
          start: args.startTimestamp,
          end: args.endTimestamp,
        };
        if (timestamps.start instanceof Date) {
          timestamps.start = Math.round(timestamps.start.getTime());
        }
        if (timestamps.end instanceof Date) {
          timestamps.end = Math.round(timestamps.end.getTime());
        }
        if (timestamps.start > 2147483647000) {
          throw new RangeError(
            "timestamps.start must fit into a unix timestamp"
          );
        }
        if (timestamps.end > 2147483647000) {
          throw new RangeError("timestamps.end must fit into a unix timestamp");
        }
      }
      if (
        args.largeImageKey ||
        args.largeImageText ||
        args.smallImageKey ||
        args.smallImageText
      ) {
        assets = {
          large_image: args.largeImageKey,
          large_text: args.largeImageText,
          small_image: args.smallImageKey,
          small_text: args.smallImageText,
        };
      }
      if (args.partySize || args.partyId || args.partyMax) {
        party = { id: args.partyId };
        if (args.partySize || args.partyMax) {
          party.size = [args.partySize, args.partyMax];
        }
      }
      if (args.matchSecret || args.joinSecret || args.spectateSecret) {
        secrets = {
          match: args.matchSecret,
          join: args.joinSecret,
          spectate: args.spectateSecret,
        };
      }

      return this.request(RPCCommands.SET_ACTIVITY, {
        pid,
        activity: {
          state: args.state,
          details: args.details,
          timestamps,
          assets,
          party,
          secrets,
          instance: !!args.instance,
        },
      });
    }

    /**
     * Clears the currently set presence, if any. This will hide the "Playing X" message
     * displayed below the user's name.
     * @param {number} [pid] The application's process ID. Defaults to the executing process' PID.
     * @returns {Promise}
     */
    clearActivity(pid = getPid()) {
      return this.request(RPCCommands.SET_ACTIVITY, {
        pid,
      });
    }

    /**
     * Invite a user to join the game the RPC user is currently playing
     * @param {User} user The user to invite
     * @returns {Promise}
     */
    sendJoinInvite(user) {
      return this.request(RPCCommands.SEND_ACTIVITY_JOIN_INVITE, {
        user_id: user.id || user,
      });
    }

    /**
     * Request to join the game the user is playing
     * @param {User} user The user whose game you want to request to join
     * @returns {Promise}
     */
    sendJoinRequest(user) {
      return this.request(RPCCommands.SEND_ACTIVITY_JOIN_REQUEST, {
        user_id: user.id || user,
      });
    }

    /**
     * Reject a join request from a user
     * @param {User} user The user whose request you wish to reject
     * @returns {Promise}
     */
    closeJoinRequest(user) {
      return this.request(RPCCommands.CLOSE_ACTIVITY_JOIN_REQUEST, {
        user_id: user.id || user,
      });
    }

    createLobby(type, capacity, metadata) {
      return this.request(RPCCommands.CREATE_LOBBY, {
        type,
        capacity,
        metadata,
      });
    }

    updateLobby(lobby, { type, owner, capacity, metadata } = {}) {
      return this.request(RPCCommands.UPDATE_LOBBY, {
        id: lobby.id || lobby,
        type,
        owner_id: (owner && owner.id) || owner,
        capacity,
        metadata,
      });
    }

    deleteLobby(lobby) {
      return this.request(RPCCommands.DELETE_LOBBY, {
        id: lobby.id || lobby,
      });
    }

    connectToLobby(id, secret) {
      return this.request(RPCCommands.CONNECT_TO_LOBBY, {
        id,
        secret,
      });
    }

    sendToLobby(lobby, data) {
      return this.request(RPCCommands.SEND_TO_LOBBY, {
        id: lobby.id || lobby,
        data,
      });
    }

    disconnectFromLobby(lobby) {
      return this.request(RPCCommands.DISCONNECT_FROM_LOBBY, {
        id: lobby.id || lobby,
      });
    }

    updateLobbyMember(lobby, user, metadata) {
      return this.request(RPCCommands.UPDATE_LOBBY_MEMBER, {
        lobby_id: lobby.id || lobby,
        user_id: user.id || user,
        metadata,
      });
    }

    getRelationships() {
      const types = Object.keys(RelationshipTypes);
      return this.request(RPCCommands.GET_RELATIONSHIPS).then((o) =>
        o.relationships.map((r) => ({
          ...r,
          type: types[r.type],
        }))
      );
    }

    /**
     * Subscribe to an event
     * @param {string} event Name of event e.g. `MESSAGE_CREATE`
     * @param {Object} [args] Args for event e.g. `{ channel_id: '1234' }`
     * @param {Function} callback Callback when an event for the subscription is triggered
     * @returns {Promise<Object>}
     */
    subscribe(event, args, callback) {
      if (!callback && typeof args === "function") {
        callback = args;
        args = undefined;
      }
      return this.request(RPCCommands.SUBSCRIBE, args, event).then(() => {
        const subid = subKey(event, args);
        this._subscriptions.set(subid, callback);
        return {
          unsubscribe: () =>
            this.request(RPCCommands.UNSUBSCRIBE, args, event).then(() =>
              this._subscriptions.delete(subid)
            ),
        };
      });
    }

    /**
     * Destroy the client
     */
    async destroy() {
      this.transport.close();
    }
  }

  return new RPCClient();
}

const sameWidthModifier = {
  name: "sameWidth",
  enabled: true,
  phase: "beforeWrite",
  requires: ["computeStyles"],
  fn: ({ state }) => {
    state.styles.popper.width = `${state.rects.reference.width}px`;
  },
  effect: ({ state }) => {
    state.elements.popper.style.width = `${state.elements.reference.offsetWidth}px`;
  },
},
  offsetModifier = {
    name: "offset",
    options: {
      offset: [0, 5],
    },
  },
  preventOverflowModifier = {
    name: "preventOverflow",
    options: {
      mainAxis: false,
    },
  };

const DEFAULT_CONFIG = {
  recordLog: {
    topLevel: `**Type:** {{type}}
**Co-host:** {{coHosts}}
**Spectators:** {{spectators}}
**Went over:** {{wentOver}}

__**Attendees**__

{{attendees}}

**Notes:** {{notes}}`,
    rankSubset: `**{{rank}}**
{{attendees}}`,
    attendeeRow: `> {{username}}{{scores}}{{outcome}}{{award}}{{notes}}`,
    attendeeScores: ` {{totalScore}} {{totalPercentage}}`,
    activityScore: `[{{score}}/{{maxScore}}]`,
    totalScore: `[{{score}}/{{maxScore}}]`,
    totalPercentage: `[{{percentage}}%]`,
    activityScoresSep: " ",
    attendeeOutcome: ` [{{outcome}}]`,
    passed: "passed",
    failed: "failed",
    dismissed: "dismissed",
    leftNoDismissal: "left without dismissal",
    award: " [90%+]",
    attendeeNotes: " ({{notes}})",
    wentOver: "> {{row}}",
    NAValue: "N/A",
  },
  dateFormat: "MM/DD/YYYY",
};

window.$ = window.jQuery = require("jquery");

document.addEventListener("DOMContentLoaded", () => {
  const trainingTypes = new Collection()
    .set(1, "Practical Examination")
    .set(2, "Cadet Orientation")
    .set(3, "Standard Training")
    .set(4, "Combative Training")
    .set(5, "Theory Examination")
    .set(6, "DEA Raid/Riot");

  const activityTypes = new Collection()
    .set(1, "Guidelines questions")
    .set(2, "Multi activity")
    .set(3, "Simple activity");

  const groupRanks = new Collection()
    .set(1, "21083192")
    .set(2, "21083191")
    .set(3, "21083415")
    .set(4, "109310811")
    .set(5, "21083416")
    .set(6, "21083417")
    .set(7, "21083427");

  const outcomes = new Collection()
    .set(1, "passed")
    .set(2, "failed")
    .set(3, "dismissed")
    .set(4, "leftNoDismissal");

  const ranks = new Collection()
    .set(1, "Cadets")
    .set(2, "Juniors")
    .set(3, "Sentinels")
    .set(4, "Specialists")
    .set(5, "Seniors")
    .set(6, "Lieutenants")
    .set(7, "Captains");

  const questionsMarks = new Collection()
    .set(false, 0)
    .set(null, 0.5)
    .set(true, 1);

  const dateFormats = new Collection()
    .set(1, "MM/DD/YYYY")
    .set(2, "DD/MM/YYYY");

  const trainingVCs = [
    "906861296404815912",
    "906861340046536704",
    "906861368936910888",
  ];

  function s(a) {
    return a > 1 ? "s" : "";
  }

  function serializeFileName(s) {
    return s.toLowerCase().replace(/(?:\s|\/|:|\||\*|"|<|>|\?)+/g, "-");
  }

  function makeSwalToast(params) {
    return Swal.fire({
      toast: true,
      timer: 5e3,
      timerProgressBar: true,
      position: "bottom-end",
      showConfirmButton: false,
      ...params,
    });
  }

  function openModal({
    modalClass = "size",
    backdropDissmissable = false,
    closeFunction = closeModal,
    title,
    headerClass,
    bodyClass,
    $footerContent,
  }) {
    $(".modalContainer")
      .empty()
      .append(
        `<div class="backdrop"></div><div class="modal"><div class="modalInner"><div class="modalContent ${modalClass}"></div></div></div>`
      );
    if (backdropDissmissable) $(".backdrop").click(closeFunction);

    const $header =
      $(`<div class="flex directionRow justifyStart alignCenter noWrap modalHeader">
			<h4 class="modalH4 modalTitle size16 height20 weightSemiBold white modalHeaderTitle">${title}</h4>
		</div>`).addClass(headerClass);
    $header.append(
      $(
        `<button class="modalClose" tabindex="-1"><i class="fas fa-times"></i></button>`
      ).click(closeFunction)
    );

    const $body = $(`<div class="modalScrollerWrap">
			<div class="modalScroller modalInnerContent modalContentContainer modalContentBody"></div>
		</div>`);
    $body.find(".modalContentBody").addClass(bodyClass);

    const $footer = $(
      `<div class="flex justifyEnd alignStretch noWrap modalFooter"></div>`
    ).append($footerContent);

    $(".modalContent").append($header).append($body);
    if ($footerContent) $(".modalContent").append($footer);
  }

  function closeModal() {
    $(".modalContainer").empty();
  }

  function modalCancel(handler = closeModal) {
    return $(
      `<button class="lookLink mediumButton" tabindex="-1">Cancel</button>`
    ).click(handler);
  }

  function playTutorial() {
    const items = [
      {
        selector: ".addAttendee",
        title: "Attendees",
        description:
          "This table is your attendees dashboard. You can add new attendees by clicking this fancy button.",
      },
      {
        selector: ".attendeeUsername",
        title: "Attendee name",
        description:
          "There, you can set the username of an attendee. The autocomplete retrives members from the group from Cadet to Specialist.<br/><strong>By using the autocomplete, their rank is also automatically set!</strong>",
      },
      {
        selector: $typeSelect,
        title: "Training type",
        description:
          "It's time to choose what you want to host, right? It is important to set this as it affects the behavior of the app.",
      },
      {
        selector: ".newActivityButton",
        title: "Activities",
        description: `<p class="marginBottomSmall">Now that we know what type we\'re doing, let\'s add some activities to our training.<br/>There are 3 different types of activity:</p>
				<ul class="styledList marginBottomSmall">
					<li>
						<h2 class="size18 weightSemiBold white">Guidelines questions</h2>
						<p>As the name suggests, this type is designed for guidelines questions exclusively. It allows fast grading while setting your own questions and answers.</p>
					</li>
					<li>
						<h2 class="size18 weightSemiBold white">Multi activity</h2>
						<p>This type provides multiple grading tabs every of which has the same amount of allocated marks.</p>
					</li>
					<li>
						<h2 class="size18 weightSemiBold white">Simple activity</h2>
						<p>This type is similar to multi activities, except it has only one grading tab. It can be set as bonus.</p>
					</li>
				</ul>
				<p class="marginBottomSmall">We'll explore them all!</p>`,
      },
      {
        action: () => {
          openModal({
            modalClass: "sizeMedium",
            title: `New activity: ${activityTypes.get(1)}`,
            bodyClass: "modalForm",
            $footerContent: modalCancel().add(
              $(
                `<button class="lookFilled colorWhite widthFitContent" tabindex="-1">Create activity</button>`
              )
            ),
          });

          const { addQuestion } = guidelinesQuestionsSettingsModalBody(
            () => { }
          );
          addQuestion("My first question?", "The very answer!");
          addQuestion("Another question?", "And another answer.");
        },
        selector: ".modalContent",
        title: "Guidelines questions",
        description:
          "There, you can add or remove as many questions as you want.<br/><strong>The total marks field refers to how much this activity will weigh in the final score.</strong>",
      },
      {
        action: () => {
          openModal({
            title: `New activity: ${activityTypes.get(2)}`,
            bodyClass: "modalForm",
            $footerContent: modalCancel().add(
              $(
                `<button class="lookFilled colorWhite widthFitContent" tabindex="-1">Create activity</button>`
              )
            ),
          });

          const { $nameInput, addItem } = multiActivitySettingsModalBody(
            () => { }
          );
          $nameInput.val("Formations");
          addItem("Riot");
          addItem("Raid");
        },
        selector: ".modalContent",
        title: "Multi activity",
        description:
          "There, you can choose a name and add or remove as many items as you want.<br/>The item marking scheme field defines how many marks every item will be graded out of.<br/>Feel free to use whatever item marking scheme fits you,<br/>the score will be scaled to the total marks automatically.<br/><strong>The total marks field refers to how much this activity will weigh in the final score.</strong>",
      },
      {
        action: () => {
          openModal({
            title: `New activity: ${activityTypes.get(3)}`,
            bodyClass: "modalForm",
            $footerContent: modalCancel().add(
              $(
                `<button class="lookFilled colorWhite widthFitContent" tabindex="-1">Create activity</button>`
              )
            ),
          });

          const { $nameInput, $markingSchemeInput } =
            simpleActivitySettingsModalBody(() => { });
          $nameInput.val("Class D brief");
          $markingSchemeInput.val(6);
        },
        selector: ".modalContent",
        title: "Simple activity",
        description:
          "There, you can choose a name but there's only one grading tab. It can be set as a bonus.<br/>The marking scheme field defines how many marks it will be graded out of.<br/>Feel free to use whatever marking scheme fits you,<br/>the score will be scaled to the total marks automatically.<br/><strong>The total marks field refers to how much this activity will weigh in the final score.</strong>",
      },
      {
        action: () => {
          closeModal();
          multiActivity(
            {
              name: "Formations",
              totalMarks: 3,
              items: new Collection()
                .set(AUTO_INCREMENT++, "Riot")
                .set(AUTO_INCREMENT++, "Raid"),
              itemMarkingScheme: 1,
            },
            true
          );
        },
        selector: ".activityGrading",
        title: "Grading an activity",
        description:
          "I have created an activity for you.<br/>Click this button to grade all attendees at a time, item by item.",
      },
      {
        selector: ".activitySettings",
        title: "Editing an activity",
        description:
          "Click this button to show a modal similar to the one used for creating this activity, allowing any edits to be made.<br/><strong>This is also where to delete an activity</strong>.",
      },
      {
        selector: ".attendeeActivityGrading",
        title: "Grading an activity for an attendee",
        description:
          "Click this button to grade a specific attendee throughout all the items of an activity.",
      },
      {
        selector: ".attendeeResult",
        title: "Outcomes",
        description: `<p class="marginBottomSmall">Now that we have attendees and activities, let\'s take a look at attendees\' outcome.<br/>Click this button to set the outcome of an attendee.<br/>The following types of outcome are available:</p>
				<ul class="styledList marginBottomSmall">
					<li class="white weightSemiBold flex">
						<button class="ghostButton attendeeResult pending marginRight8" tabindex="-1"><i class="fas fa-clock"></i></button> No outcome yet
					</li>
					<li class="white weightSemiBold flex">
						<button class="ghostButton attendeeResult passed marginRight8" tabindex="-1"><i class="fas fa-check-square"></i></button> Passed
					</li>
					<li class="white weightSemiBold flex">
						<button class="ghostButton attendeeResult failed marginRight8" tabindex="-1"><i class="fas fa-ban"></i></button> Failed
					</li>
					<li class="white weightSemiBold flex">
						<button class="ghostButton attendeeResult dismissed marginRight8" tabindex="-1"><i class="fas fa-user-clock"></i></button> Dismissed
					</li>
					<li class="white weightSemiBold flex">
						<button class="ghostButton attendeeResult leftNoDismissal marginRight8" tabindex="-1"><i class="fas fa-user-times"></i></button> Left without dismissal
					</li>
				</ul>`,
      },
      {
        selector: ".resultThead",
        title: "Scores sync",
        description:
          "If you're a big lazy like me, just click this button once you're done grading everything.<br/>It'll automatically synchronize the outcome of every attendee with their score.<br/><strong>Note: attendees that were dismissed or left without dismissal will be ignored.</strong>",
      },
      {
        selector: ".attendeeAward",
        title: "Awards",
        description:
          "Click there to mark whether the attendee got 90%+ for Specialists.",
      },
      {
        selector: ".attendeeNotesButton",
        title: "Attendee notes",
        description:
          "Click this button to write some notes about an attendee. These will appear on the record log.",
      },
      {
        selector: ".attendeeDragHandle",
        title: "Attendee dragging",
        description:
          "Want to re-order your attendees? No prob, this handle allows you to drag'n'sort an attendee.",
      },
      {
        selector: ".vcCheckerThead",
        title: "VC checker",
        description:
          "This is a awesome feature. Enabling the VC checker will <strong>match the attendees' username with the people live in your current VC</strong>.<br/>Thus, it's easy to figure out who's not in VC before starting your training or who disconnected in the middle of it.<br/>Click here to enable it, then you will be prompted to allow the application on your Discord client.<br/>It can be disabled at anytime and will die as soon as you close the application otherwise.<br/><strong>Note: this will only work in the SD Discord server training VC's.</strong>",
      },
      {
        selector: ".coHostsWrapper",
        title: "Co-hosts",
        description:
          "There, you can add or remove as many co-hosts as you want. The autocomplete retrives members from the group from Specialists to Captains.",
      },
      {
        selector: ".spectatorsWrapper",
        title: "Spectators",
        description:
          "There, you can add or remove as many spectators as you want. The autocomplete retrives members from the group from Seniors to Lieutenants.",
      },
      {
        selector: ".wentOver textarea",
        title: "Went over",
        description:
          "Everytime a new activity is created, its name will be appended here. Though, feel free to edit this as pure text.",
      },
      {
        selector: ".recordLogButton",
        title: "Record log",
        description:
          "Click this button to get your record log ready to be copied and pasted!",
      },
      {
        selector: ".saveTraining",
        title: "Saving trainings",
        description:
          "Trainings can be saved as a file, allowing them to be re-opened later with the app. Everything will be stored.",
      },
      {
        selector: ".saveTemplate",
        title: "Saving templates",
        description:
          "Templates are a different type of training files. They only include the structure of the training, such as the type, activities and the went over.<br/>Some templates are already included in this app, but you may create more.<br/>To do so, elaborate the structure of your training from scratch and use this button to save it.",
      },
      {
        selector: ".openFile",
        title: "Open file",
        description:
          'Click here to browse through your computer\'s files and open either a template or training file.<br/><strong>Note: training and template files can only be loaded through this button. Opening them directly from your file explorer will not work.</strong><br/><strong>Another note: trainings are autosaved every 30 seconds. Open "autosave.json" to recover your last training.</strong>',
      },
      {
        selector: ".customize",
        title: "Customize",
        description:
          "Here you can customize the outputted record log. You can also change other stuff like the background theme. <br/><strong>You might achieve unwanted behavior if you don't exactly know what you're doing.</strong>",
      },
    ];

    const $overlay = $(`<div class="tutorialOverlay"></div>`)
      .append(
        $(`<div>
			<h1 class="size28 weightSemiBold white">Hello there, looks like you're new!</h1>
			<p class="marginBottomSmall">We're gonna tour this application, if you don't mind. If you wish to skip this tutorial, you'll still be able to play it again later.</p>
		</div>`).append(
          $(`<div class="flex"></div>`)
            .append(
              $(
                `<button class="lookFilled colorGreen marginRightSmall">Let's get started!</button>`
              ).click(async () => {
                $overlay.empty();
                for (const { selector, title, description, action } of items) {
                  if (action) action();
                  await spot(
                    typeof selector === "string" ? $(selector) : selector,
                    200,
                    title,
                    description
                  );
                }
                if (popout) popout.destroy();
                popout = null;
                $overlay
                  .css("background", "")
                  .empty()
                  .append(
                    $(`<div>
				<h1 class="size28 weightSemiBold white">Tour over!</h1>
				<p class="marginBottom8">Though, if you're a nerd, you might want to have a look at these lovely shortcuts:</p>
				<div class="flex flexWrap" style="max-width: 900px;">
					<div class="marginRightSmall marginBottomSmall">
						<p class="marginBottom8 white weightSemiBold">Attendee username inputs:</p>
						<div class="flex alignCenter marginBottom8">
							<span class="shortcut">Shift</span><span class="shortcutPlus">+</span><span class="shortcut">Enter</span><span class="marginLeft8">Add a new attendee</span>
						</div>
						<div class="flex alignCenter marginBottomSmall">
							<span class="shortcut">Shift</span><span class="shortcutPlus">+</span><span class="shortcut">Del</span><span class="marginLeft4">(with the input empty)</span><span class="marginLeft8">Delete this attendee</span>
						</div>
					</div>
					<div class="marginRightSmall marginBottomSmall">
						<p class="marginBottom8 white weightSemiBold">Co-host username inputs:</p>
						<div class="flex alignCenter marginBottom8">
							<span class="shortcut">Shift</span><span class="shortcutPlus">+</span><span class="shortcut">Enter</span><span class="marginLeft8">Add a new co-host</span>
						</div>
						<div class="flex alignCenter marginBottomSmall">
							<span class="shortcut">Shift</span><span class="shortcutPlus">+</span><span class="shortcut">Del</span><span class="marginLeft4">(with the input empty)</span><span class="marginLeft8">Delete this co-host</span>
						</div>
					</div>
					<div class="marginRightSmall marginBottomSmall">
						<p class="marginBottom8 white weightSemiBold">Guidelines questions answer inputs:</p>
						<div class="flex alignCenter marginBottomSmall">
							<span class="shortcut">Shift</span><span class="shortcutPlus">+</span><span class="shortcut">Enter</span><span class="marginLeft8">Add a new question</span>
						</div>
					</div>
					<div class="marginRightSmall marginBottomSmall">
						<p class="marginBottom8 white weightSemiBold">Multi activity item inputs:</p>
						<div class="flex alignCenter marginBottomSmall">
							<span class="shortcut">Shift</span><span class="shortcutPlus">+</span><span class="shortcut">Enter</span><span class="marginLeft8">Add a new item</span>
						</div>
					</div>
					<div class="marginRightSmall marginBottomSmall">
						<p class="marginBottom8 white weightSemiBold">Autocomplete:</p>
						<div class="marginBottomSmall">Similar to Discord</div>
					</div>
					<div class="marginRightSmall marginBottomSmall">
						<p class="marginBottom8 white weightSemiBold">All inputs:</p>
						<div class="flex alignCenter marginBottom8">
							<span class="shortcut">Tab</span><span class="marginLeft8">Navigate to next input</span>
						</div>
						<div class="flex alignCenter marginBottom8">
							<span class="shortcut">Shift</span><span class="shortcutPlus">+</span><span class="shortcut">Tab</span><span class="marginLeft8">Navigate to previous input</span>
						</div>
						<div class="flex alignCenter marginBottomSmall">
							<span class="shortcut">Enter</span><span class="marginLeft4">(in modal)</span><span class="marginLeft8">Submit the modal</span>
						</div>
					</div>
				</div>
			</div>`)
                      .append(
                        `<button class="lookFilled colorGreen">Let me go now!!!</button>`
                      )
                      .click(() => {
                        localStorage.setItem("seenTutorial", true);
                        $overlay.remove();
                      })
                  );
              })
            )
            .append(
              $(
                `<button class="lookFilled colorWhite">I don't care, skip this</button>`
              ).click(() => {
                localStorage.setItem("seenTutorial", true);
                $overlay.remove();
              })
            )
        )
      )
      .appendTo("#app-mount");

    let fromTop = 0,
      fromLeft = 0,
      fromSize = 0,
      popout;

    function spot($elem, duration, title, description) {
      return new Promise((res) => {
        const { y, x, width, height } = $elem[0].getBoundingClientRect(),
          size =
            Math.round(Math.sqrt((width / 2) ** 2 + (height / 2) ** 2)) + 20,
          top = y + height / 2,
          left = x + width / 2;
        let i = 0;

        function step() {
          i++;
          $overlay.css({
            background: `radial-gradient(circle at top ${fromTop + ((top - fromTop) * i) / (duration * 0.06)
              }px left ${fromLeft + ((left - fromLeft) * i) / (duration * 0.06)
              }px, transparent ${fromSize + ((size - fromSize) * i) / (duration * 0.06)
              }px, rgba(0, 0, 0, 0.8) ${fromSize + ((size - fromSize) * i) / (duration * 0.06) + 3
              }px)`,
          });
          if (i < duration * 0.06) requestAnimationFrame(step);
          else {
            fromTop = top;
            fromLeft = left;
            fromSize = size;
            if (popout) popout.destroy();
            $overlay.empty();
            popout = Popper.createPopper(
              $elem[0],
              $(
                `<div><h1 class="size28 weightSemiBold white">${title}</h1><div class="marginBottomSmall">${description}</div></div>`
              )
                .append(
                  $(
                    `<button class="lookFilled colorBlue">Got it, next!</button>`
                  ).click(() => res())
                )
                .appendTo($overlay)[0],
              {
                placement: "right",
                modifiers: [
                  {
                    name: "preventOverflow",
                    options: {
                      padding: 20,
                    },
                  },
                  {
                    name: "offset",
                    options: {
                      offset: [0, 40],
                    },
                  },
                ],
              }
            );
          }
        }
        requestAnimationFrame(step);
      });
    }
  }

  const activities = new Collection(),
    attendees = new Collection(),
    coHosts = new Collection(),
    spectators = new Collection(),
    client = RPCClient();

  let AUTO_INCREMENT,
    attendeesAC = new Collection(),
    coHostsAC = new Collection(),
    spectatorsAC = new Collection(),
    config,
    VCCheckerInt;

  if (fs.existsSync("./config.json"))
    config = deepmerge(
      DEFAULT_CONFIG,
      JSON.parse(fs.readFileSync("./config.json"))
    );
  else config = DEFAULT_CONFIG;

  function AIArray(n) {
    const arr = [];
    for (let i = 0; i < n; i++) arr.push(AUTO_INCREMENT++);
    return arr;
  }

  function updateVoiceStatuses() {
    client.getSelectedVoiceChannel().then((channel) => {
      const users = channel.voice_states.map((user) => user.nick);
      attendees.forEach((attendee) => {
        if (attendee.$usernameInput.val()) {
          if (users.includes(attendee.username))
            attendee.find(".vc").addClass("vcIn").removeClass("vcOut");
          else attendee.find(".vc").addClass("vcOut").removeClass("vcIn");
        } else attendee.find(".vc").removeClass("vcIn vcOut");
      });
    });
  }

  function updateAttendeeIndexes() {
    attendees.forEach(
      (attendee) =>
        (attendee.index = $(".attendees tbody tr").index(attendee[0]))
    );
  }

  function updateAttendeeCounter() {
    $(".attendeeCounter").text(`Attendees: ${attendees.size}`);
  }

  function replaceVars(text, variables) {
    Object.entries(variables).forEach(
      ([name, value]) =>
        (text = text.replace(new RegExp(`\{\{${name}\}\}`, "g"), value))
    );
    return text;
  }

  function mapAttendeeRecord(rank) {
    const rankedAttendees = attendees.filter(
      (attendee) => attendee.rank === rank
    );
    if (!rankedAttendees.size) return config.recordLog.NAValue;
    return rankedAttendees
      .map((attendee) => {
        const score = attendee.getScore();
        return replaceVars(config.recordLog.attendeeRow, {
          username: attendee.username,
          scores:
            $typeSelect.value === 2 || [3, 4].includes(attendee.result)
              ? ""
              : replaceVars(config.recordLog.attendeeScores, {
                activitiesScores: activities
                  .map((activity) => {
                    const score = activity.getAttendeeScore(attendee.id);
                    return replaceVars(config.recordLog.activityScore, {
                      activityName: activity.name,
                      score: score[0],
                      maxScore: score[1],
                    });
                  })
                  .join(config.recordLog.activityScoresSep),
                totalScore: replaceVars(config.recordLog.totalScore, {
                  score: score[0],
                  maxScore: score[1],
                }),
                totalPercentage: replaceVars(
                  config.recordLog.totalPercentage,
                  {
                    percentage: attendee.getScore100(),
                  }
                ),
              }),
          outcome: replaceVars(config.recordLog.attendeeOutcome, {
            outcome: attendee.result
              ? config.recordLog[outcomes.get(attendee.result)].toUpperCase()
              : "",
          }),
          award: attendee.award ? config.recordLog.award.toUpperCase() : "",
          notes: attendee.notes
            ? replaceVars(config.recordLog.attendeeNotes, {
              notes: attendee.notes,
            })
            : "",
        });
      })
      .join("\n");
  }

  function recordLog() {
    return replaceVars(config.recordLog.topLevel, {
      type: $typeSelect.value ? trainingTypes.get($typeSelect.value) : "",
      coHosts: coHosts.size
        ? coHosts.map((coHost) => coHost.username).join(", ")
        : config.recordLog.NAValue,
      spectators: spectators.size
        ? spectators.map((spectator) => spectator.username).join(", ")
        : config.recordLog.NAValue,
      wentOver: getWentOver().length
        ? `\n${getWentOver()
          .map((row) =>
            replaceVars(config.recordLog.wentOver, {
              row,
            })
          )
          .join("\n")}`
        : "",
      attendees: ([1, 2, 5].includes($typeSelect.value) ? [1] : [1, 2, 3])
        .map((rank) =>
          replaceVars(config.recordLog.rankSubset, {
            rank: ranks.get(rank),
            attendees: mapAttendeeRecord(rank),
          })
        )
        .join("\n\n"),
      date: $dateInput.val(),
      notes: $notesInput.val(),
    });
  }

  function select(options = new Collection(), unselected) {
    let $dropdown,
      currentOptionID = null;
    const $elem = $('<div class="select"></div>');

    $elem
      .append(
        $(
          `<button tabindex="-1"><span class="selectText"></span><i class="fas fa-chevron-down chevronDown"></i></button>`
        ).click(() => {
          if ($dropdown) return;
          $dropdown = $(`<div class="selectDropdown"></div>`);
          $elem.options.forEach((option, id) =>
            $dropdown.append(
              $(`<div class="selectDropdownItem">${option.name}</div>`).click(
                () => {
                  close();
                  setOption(id);
                  $elem.trigger("input");
                }
              )
            )
          );
          $elem.find(".selectDropdownWrapper").append($dropdown);
          setImmediate(() => $(document).click(clickHandler));
        })
      )
      .append('<div class="selectDropdownWrapper"></div>');

    $elem.options = options;

    function clickHandler(e) {
      if (!$(e.target).closest(".selectDropdownWrapper").length) close();
    }

    function setOption(id) {
      if (id === null) {
        currentOptionID = null;
        $elem.find(".selectText").addClass("unselected").text(unselected);
      } else {
        currentOptionID = id;
        $elem
          .find(".selectText")
          .removeClass("unselected")
          .text($elem.options.get(id).name);
      }
      $elem.trigger("change");
    }

    function close() {
      $dropdown.remove();
      $dropdown = null;
      $(document).off("click", clickHandler);
    }

    Object.assign($elem, {
      setOption,
    });
    Object.defineProperty($elem, "value", {
      get: () =>
        currentOptionID === null
          ? null
          : $elem.options.get(currentOptionID).value,
    });

    setOption(null);

    return $elem;
  }

  function input({
    inputClass = "input",
    validator,
    enter,
    shiftEnter,
    value,
  }) {
    const $elem = $(`<input type="text" class="${inputClass} invalid">`)
      .on("input", update)
      .on("keydown", (e) => {
        if (e.shiftKey && e.which === 13 && $elem.shiftEnter)
          $elem.shiftEnter();
        else if (e.which === 13 && $elem.enter) $elem.enter();
      });

    if (value !== undefined) val(value);
    if (enter) setEnter(enter);
    if (shiftEnter) setShiftEnter(shiftEnter);
    if (validator) setValidator(validator);

    function isValid() {
      return $elem.validator ? $elem.validator($elem.val()) : true;
    }

    function setValidator(validator) {
      $elem.validator = validator;
      return $elem;
    }

    function setEnter(enter) {
      $elem.enter = enter;
      return $elem;
    }

    function setShiftEnter(shiftEnter) {
      $elem.shiftEnter = shiftEnter;
      return $elem;
    }

    function update() {
      isValid() ? $elem.removeClass("invalid") : $elem.addClass("invalid");
    }

    function val(value) {
      if (value !== undefined) {
        $elem[0].value = value;
        update();
        return $elem;
      } else return $elem[0].value;
    }

    Object.assign($elem, {
      isValid,
      setEnter,
      setShiftEnter,
      setValidator,
      val,
    });

    update();

    return $elem;
  }

  function autocompleteInput(props, coll, { getElement = (e) => e, cb } = {}) {
    const $input = input(props)
      .on("input focusin", updateAutocomplete)
      .addClass("autocompleteInput");
    const $elements = new Collection();
    let popout, $autocomplete, currentElementID;

    function updateAutocomplete() {
      if (!$input.val()) return hideAutocomplete();
      if (!coll.size) return hideAutocomplete();

      const search = $input
        .val()
        .trim()
        .replace(/[-\/\\^$*+?.()|[\]{}]/g, "\\$&");
      const elements = coll
        .filter((element) => new RegExp(search, "gi").test(getElement(element)))
        .sort((a) =>
          new RegExp(`^${search}`, "gi").test(getElement(a)) ? -1 : 0
        );
      if (!elements.size) return hideAutocomplete();

      if (!popout) {
        $input.addClass("hasAutocomplete").on("keydown", keydownHandler);
        $autocomplete = $(`<div class="autocomplete"></div>`).appendTo(
          props.$popoutContainer || $(".popoutsContainer")
        );
        const modifiers = [sameWidthModifier];
        if (props.$popoutContainer) modifiers.push(preventOverflowModifier);
        popout = Popper.createPopper($input[0], $autocomplete[0], {
          modifiers,
          placement: "bottom",
        });
        setImmediate(() => $(document).click(clickHandler));
      }

      $autocomplete.empty();
      $elements.clear();
      elements.slice(0, 5).forEach((element, id, i) => {
        const $elem = $(`<div>${getElement(element)}</div>`)
          .appendTo($autocomplete)
          .hover(select)
          .click(selectCurrent);
        if (i === 0) select();

        function select() {
          $elements.forEach((element) => element.unselect());
          $elem.addClass("selected");
          currentElementID = id;
        }

        function unselect() {
          $elem.removeClass("selected");
        }

        Object.assign($elem, {
          select,
          unselect,
        });

        $elements.set(id, $elem);
      });
    }

    function next() {
      const keyArray = $elements.keyArray();
      const newI = (keyArray.indexOf(currentElementID) + 1) % $elements.size;
      $elements.get(keyArray[newI]).select();
    }

    function previous() {
      const keyArray = $elements.keyArray();
      const newI =
        (keyArray.indexOf(currentElementID) - 1 + $elements.size) %
        $elements.size;
      $elements.get(keyArray[newI]).select();
    }

    function selectCurrent() {
      const element = coll.get(currentElementID);
      $input.val(getElement(element)).trigger("input");
      if (cb) cb(element);
      hideAutocomplete();
    }

    function hideAutocomplete() {
      if (!popout) return;
      $input.removeClass("hasAutocomplete").off("keydown", keydownHandler);
      popout.state.elements.popper.remove();
      popout.destroy();
      popout = null;
      currentElementID = null;
      $(document).off("click", clickHandler);
    }

    function keydownHandler(e) {
      if (e.which === 38) {
        previous();
        e.preventDefault();
      } else if (e.which === 40) {
        next();
        e.preventDefault();
      } else if (e.which === 13) selectCurrent();
    }

    function clickHandler(e) {
      if (!$(e.target).closest(".autocompleteInput").length) hideAutocomplete();
    }

    function isAutocompleteExpanded() {
      return !!popout;
    }

    Object.assign($input, {
      isAutocompleteExpanded,
    });

    return $input;
  }

  function ghostSelect(
    options = new Collection(),
    {
      buttonClass,
      popupClass,
      defaultOptionID = options.firstKey(),
      $popoutContainer,
    }
  ) {
    let popout, optionID;
    const $elem = $(
      `<button class="ghostButton ${buttonClass}" tabindex="-1"></button>`
    ).click(() => {
      if (popout) return;
      const $dropdown = $(
        `<div class="ghostDropdown ${popupClass}"><ul></ul></div>`
      ).appendTo($popoutContainer || $(".popoutsContainer"));
      $elem.options.forEach((option, id) =>
        $dropdown.find("ul").append(
          $(
            `<li><button class="${option.class}" tabindex="-1">${option.content}</button></li>`
          ).click(() => {
            close();
            setOption(id);
            $elem.trigger("input");
          })
        )
      );
      const modifiers = [offsetModifier];
      if ($popoutContainer) modifiers.push(preventOverflowModifier);
      popout = Popper.createPopper($elem[0], $dropdown[0], {
        modifiers,
        placement: "bottom",
      });
      setImmediate(() => $(document).click(clickHandler));
    });

    $elem.options = options;

    function clickHandler(e) {
      if (!$(e.target).closest(".ghostDropdown").length) close();
    }

    function setOption(id) {
      optionID = id;
      const option = $elem.options.get(id);
      $elem
        .html(option.content)
        .removeClass($elem.options.map((e) => e.class).join(" "))
        .addClass(option.class);
      $elem.trigger("change");
    }

    function close() {
      popout.state.elements.popper.remove();
      popout.destroy();
      popout = null;
      $(document).off("click", clickHandler);
    }

    setOption(defaultOptionID);

    Object.assign($elem, {
      setOption,
    });
    Object.defineProperty($elem, "value", {
      get: () => $elem.options.get(optionID).value,
    });

    return $elem;
  }

  function dropdown(options = new Collection(), { $button, $popoutContainer }) {
    let popout;
    const $elem = $button.click(() => {
      if (popout) return;
      const $dropdown = $(`<div class="dropdown"><ul></ul></div>`).appendTo(
        $popoutContainer || $(".popoutsContainer")
      );
      $elem.options.forEach((option) =>
        $dropdown.find("ul").append(
          $(`<li><button tabindex="-1">${option.name}</button></li>`).click(
            () => {
              close();
              option.cb();
            }
          )
        )
      );
      const modifiers = [offsetModifier];
      if ($popoutContainer) modifiers.push(preventOverflowModifier);
      popout = Popper.createPopper($elem[0], $dropdown[0], {
        modifiers,
        placement: "bottom",
      });
      setImmediate(() => $(document).click(clickHandler));
    });

    $elem.options = options;

    function clickHandler(e) {
      if (!$(e.target).closest(".dropdown").length) close();
    }

    function close() {
      popout.state.elements.popper.remove();
      popout.destroy();
      popout = null;
      $(document).off("click", clickHandler);
    }

    return $elem;
  }

  function checkbox() {
    const $elem = $(`<div class="switch">
			<input type="checkbox" class="checkbox">
		</div>`).click(() => ($elem.value ? uncheck() : check()));

    function check() {
      $elem.addClass("valueChecked").value = true;
    }

    function uncheck() {
      $elem.removeClass("valueChecked").value = false;
    }

    uncheck();

    Object.assign($elem, {
      check,
      uncheck,
    });

    return $elem;
  }

  function markInput() {
    const $elem = $(`<div class="markInput"></div>`);

    const $wrongButton = $(
      `<button class="wrong" tabindex="-1"><i class="fas fa-times"></i></button>`
    ).click(() => setValue(false)),
      $halfButton = $(
        `<button class="half" tabindex="-1"><i class="fas fa-slash"></i></button>`
      ).click(() => setValue(null)),
      $correctButton = $(
        `<button class="correct" tabindex="-1"><i class="fas fa-check"></i></button>`
      ).click(() => setValue(true));

    $elem.append($wrongButton).append($halfButton).append($correctButton);

    function selectButton($button, value) {
      $elem.children().removeClass("selected");
      $button.addClass("selected");
      $elem.value = value;
    }

    function setValue(value) {
      switch (value) {
        case true:
          selectButton($correctButton, true);
          break;
        case null:
          selectButton($halfButton, null);
          break;
        case false:
        default:
          selectButton($wrongButton, false);
          break;
      }
      return $elem;
    }

    setValue();

    Object.assign($elem, {
      setValue,
    });

    return $elem;
  }

  function iconCheckbox($button, classToAdd) {
    $button.click(() => setValue(!$button.value));

    function setValue(value) {
      if (value) $button.addClass(classToAdd).value = true;
      else $button.removeClass(classToAdd).value = false;
      $button.trigger("change");
    }

    setValue();

    Object.assign($button, {
      setValue,
    });

    return $button;
  }

  function checkboxGroup(options = new Collection(), checkboxClass) {
    const checkboxes = new Collection();
    let optionID;

    function checkbox(id) {
      const $elem = $(
        `<div class="groupCheckbox ${checkboxClass}"><i class="fas fa-check"></i></div>`
      ).click(select);

      function select() {
        checkboxes.forEach(($checkbox) => $checkbox.removeClass("checked"));
        $elem.addClass("checked");
        optionID = id;
      }

      Object.assign($elem, {
        select,
      });

      return $elem;
    }

    options.forEach((option, id) => checkboxes.set(id, checkbox(id)));

    checkboxes.first().select();

    Object.defineProperty(checkboxes, "value", {
      get: () => options.get(optionID),
    });

    return checkboxes;
  }

  $(".winButtonClose").click(() => ipcRenderer.send("winClose"));
  $(".winButtonMin").click(() => ipcRenderer.send("winMin"));
  $(".winButtonMax").click(() => ipcRenderer.send("winMax"));

  async function getGroupAC() {
    attendeesAC.clear();
    coHostsAC.clear();
    spectatorsAC.clear();
    attendeesAC.merge(
      await getGroupRankUsers(1),
      await getGroupRankUsers(2),
      await getGroupRankUsers(3),
      await getGroupRankUsers(4),
      await getGroupRankUsers(5),
      await getGroupRankUsers(6),
      await getGroupRankUsers(7),
    );
    coHostsAC.merge(await getGroupRankUsers(4), await getGroupRankUsers(5), await getGroupRankUsers(6), await getGroupRankUsers(7));
    spectatorsAC.merge(await getGroupRankUsers(5), await getGroupRankUsers(6), await getGroupRankUsers(7));
  }

  async function getGroupRankUsers(rank) {
    let request,
      cursor = "";
    const users = new Collection();
    do {
      try {
        request = await snekfetch.get(
          `https://groups.roblox.com/v1/groups/3069581/roles/${groupRanks.get(
            rank
          )}/users?cursor=${cursor}&limit=100&sortOrder=Desc`
        );
      } catch {
        break;
      }
      if (!request.ok) break;
      request.body.data.forEach((user) =>
        users.set(AUTO_INCREMENT++, {
          rank,
          username: user.username,
        })
      );
      cursor = request.body.nextPageCursor;
    } while (cursor);
    return users;
  }

  const $typeSelect = select(
    new Collection()
      .set(1, {
        name: trainingTypes.get(1),
        value: 1,
      })
      .set(2, {
        name: trainingTypes.get(2),
        value: 2,
      })
      .set(3, {
        name: trainingTypes.get(3),
        value: 3,
      })
      .set(4, {
        name: trainingTypes.get(4),
        value: 4,
      })
      .set(5, {
        name: trainingTypes.get(5),
        value: 5,
      })
      .set(5, {
        name: trainingTypes.get(6),
        value: -1,
      }),
    "Training type"
  );
  $typeSelect.on("change", () => {
    attendees.forEach((attendee) => attendee.updateScore());
    activities.forEach((activity) =>
      activity.tds.forEach(($td, attendeeID) =>
        $td.updateScore(activity.getAttendeeScore(attendeeID))
      )
    );
  });
  $(".type").append($typeSelect);

  const $notesInput = $(".notes textarea");

  const $wentOverInput = $(".wentOver textarea");

  const $dateInput = $(`<input type="text" class="input">`).insertAfter(
    ".date .fieldName"
  );

  const $addCoHostButton = $(
    `<button class="lookFilled colorWhite widthFitContent" tabindex="-1"><i class="fas fa-user-plus marginRight4"></i> New co-host</button>`
  ).click(() => addCoHost().focus());
  $(".coHostsWrapper").append($addCoHostButton);

  const $addSpectatorButton = $(
    `<button class="lookFilled colorWhite widthFitContent" tabindex="-1"><i class="fas fa-user-plus marginRight4"></i> New spectator</button>`
  ).click(() => addSpectator().focus());
  $(".spectatorsWrapper").append($addSpectatorButton);

  function addCoHost() {
    const id = AUTO_INCREMENT++;
    const $elem = $(`<div class="coHostRow"></div>`);

    const $usernameInput = autocompleteInput(
      { inputClass: "ghostInput" },
      coHostsAC,
      {
        getElement: (element) => element.username,
      }
    );
    $usernameInput.on("keydown", (e) => {
      if ($usernameInput.isAutocompleteExpanded()) return;
      if (e.which === 13 && e.shiftKey) addCoHost().focus();
      else if (e.which === 8 && e.shiftKey && !$usernameInput.val()) {
        e.preventDefault();
        const currentI = coHosts.keyArray().indexOf(id);
        deleteCoHost();
        const toFocus = coHosts.get(
          coHosts.keyArray()[currentI] || coHosts.keyArray().slice(-1)[0]
        );
        if (toFocus) toFocus.focus();
      }
    });

    $elem
      .append($usernameInput)
      .append(
        $(
          `<button class="ghostButton coHostRowDelete" tabindex="-1"><i class="fas fa-times-circle"></i></button>`
        ).click(deleteCoHost)
      );

    $addCoHostButton.before($elem);

    function deleteCoHost() {
      $elem.remove();
      coHosts.delete(id);
    }

    function focus() {
      $usernameInput.focus();
    }

    Object.defineProperty($elem, "username", {
      get: () => $usernameInput.val().trim(),
    });
    Object.assign($elem, {
      focus,
      deleteCoHost,
    });

    coHosts.set(id, $elem);

    return $elem;
  }

  function addSpectator() {
    const id = AUTO_INCREMENT++;
    const $elem = $(`<div class="spectatorRow"></div>`);

    const $usernameInput = autocompleteInput(
      { inputClass: "ghostInput" },
      spectatorsAC,
      {
        getElement: (element) => element.username,
      }
    );
    $usernameInput.on("keydown", (e) => {
      if ($usernameInput.isAutocompleteExpanded()) return;
      if (e.which === 13 && e.shiftKey) addSpectator().focus();
      else if (e.which === 8 && e.shiftKey && !$usernameInput.val()) {
        e.preventDefault();
        const currentI = spectators.keyArray().indexOf(id);
        deleteSpectator();
        const toFocus = spectators.get(
          spectators.keyArray()[currentI] || spectators.keyArray().slice(-1)[0]
        );
        if (toFocus) toFocus.focus();
      }
    });

    $elem
      .append($usernameInput)
      .append(
        $(
          `<button class="ghostButton spectatorRowDelete" tabindex="-1"><i class="fas fa-times-circle"></i></button>`
        ).click(deleteSpectator)
      );

    $addSpectatorButton.before($elem);

    function deleteSpectator() {
      $elem.remove();
      spectators.delete(id);
    }

    function focus() {
      $usernameInput.focus();
    }

    Object.defineProperty($elem, "username", {
      get: () => $usernameInput.val().trim(),
    });
    Object.assign($elem, {
      focus,
      deleteSpectator,
    });

    spectators.set(id, $elem);

    return $elem;
  }

  function getWentOver() {
    return $wentOverInput
      .val()
      .split(/\n\r?/g)
      .filter((line) => line);
  }

  function appendWentOver(name) {
    $(".wentOver textarea").val([...getWentOver(), name].join("\n"));
  }

  function addAttendee(initSettings) {
    const id = AUTO_INCREMENT++;
    let index = Math.max(0, ...attendees.map((attendee) => attendee.index)) + 1;
    const $elem = $(`<tr>
			<td><button class="ghostButton attendeeDragHandle marginLeft4"><i class="fas fa-bars"></i></button></td>
			<td class="attendeeUsername"></td>
			<td></td>
			<td class="textCenter"><button class="ghostButton vc" tabindex="-1"><i class="fas fa-volume-up"></i></button></td>
			<td class="score"><b>0</b>/0</td>
			<td class="score"><b>0</b>%</td>
			<td class="textCenter"></td>
			<td></td>
			<td></td>
			<td></td>
		</tr>`);

    const $placeHolderTd = $(`<td style="width: 100%;"></td>`).insertAfter(
      $elem.find("td").eq(3)
    );

    const $rankInput = ghostSelect(
      new Collection()
        .set(1, {
          content: '<td>C</td>',
          class: "cadet",
          value: 1,
        })
        .set(2, {
          content: "<td>J</td>",
          class: "junior",
          value: 2,
        })
        .set(3, {
          content: "<td>S</td>",
          class: "sentinel",
          value: 3,
        })
        .set(4, {
          content: "<td>S</td>",
          class: "specialist",
          value: 4,
        })
        .set(5, {
          content: "<td>S</td>",
          class: "senior",
          value: 5,
        })
        .set(6, {
          content: "<td>L</td>",
          class: "lieutenant",
          value: 6,
        })
        .set(7, {
          content: "<td>C</td>",
          class: "captain",
          value: 7,
        }),
      {
        buttonClass: "attendeeRank",
        popupClass: "attendeeRankPopup",
        $popoutContainer: $(".tablePopoutsContainer"),
      }
    );
    $rankInput.appendTo($elem.find("td").eq(2));

    const $usernameInput = autocompleteInput(
      {
        inputClass: "ghostInput",
        $popoutContainer: $(".tablePopoutsContainer"),
      },
      attendeesAC,
      {
        getElement: (element) => element.username,
        cb: (element) => $rankInput.setOption(element.rank),
      }
    );
    $usernameInput
      .on("keydown", (e) => {
        if ($usernameInput.isAutocompleteExpanded()) return;
        if (e.which === 13 && e.shiftKey) addAttendee().focus();
        else if (
          e.which === 8 &&
          e.shiftKey &&
          !$usernameInput.val() &&
          attendees.size > 1
        ) {
          e.preventDefault();
          deleteAttendee();
          (
            attendees.find((attendee) => attendee.index === $elem.index) ||
            attendees.last()
          ).focus();
        }
      })
      .appendTo($elem.find("td").eq(1));

    const $resultInput = ghostSelect(
      new Collection()
        .set(0, {
          content: '<i class="fas fa-clock"></i>',
          class: "pending",
          value: 0,
        })
        .set(1, {
          content: '<i class="fas fa-check-square"></i>',
          class: "passed",
          value: 1,
        })
        .set(2, {
          content: '<i class="fas fa-ban"></i>',
          class: "failed",
          value: 2,
        })
        .set(3, {
          content: '<i class="fas fa-user-clock"></i>',
          class: "dismissed",
          value: 3,
        })
        .set(4, {
          content: '<i class="fas fa-user-times"></i>',
          class: "leftNoDismissal",
          value: 4,
        }),
      {
        buttonClass: "attendeeResult",
        popupClass: "attendeeResultPopup",
        $popoutContainer: $(".tablePopoutsContainer"),
      }
    );
    $elem.find("td").eq(-4).append($resultInput);

    const $awardInput = iconCheckbox(
      $(
        `<button class="ghostButton attendeeAward" tabindex="-1"><i class="fas fa-medal"></i></button>`
      ),
      "award"
    );
    $elem.find("td").eq(-3).append($awardInput);

    $elem
      .find("td")
      .eq(-2)
      .append(
        $(
          `<button class="ghostButton attendeeNotesButton" tabindex="-1"><i class="fas fa-sticky-note"></i></button>`
        ).click(() => {
          openModal({
            title: `${$elem.username}'s notes`,
            modalClass: "bodyForm",
            $footerContent: modalCancel().add(
              $(
                `<button class="lookFilled colorWhite" tabindex="-1">Save</button>`
              ).click(submit)
            ),
          });

          function submit() {
            if ($notesInput.val().trim())
              $elem.notes = $notesInput.val().trim();
            else delete $elem.notes;
            closeModal();
          }

          const $notesInput = $(`<textarea class="attendeeNotes" rows="3">`);
          $notesInput.val($elem.notes);

          $(".modalContentBody").append(
            $(`<div class="formField textareaFormField">
				<span class="fieldName">Notes:</span>
			</div>`).append($notesInput)
          );
          $notesInput.focus();
        })
      );

    $elem
      .find("td")
      .eq(-1)
      .append(
        $(
          `<button class="ghostButton attendeeRowDelete" tabindex="-1"><i class="fas fa-times-circle"></i></button>`
        ).click(() => {
          if (attendees.size < 2) return;
          openModal({
            backdropDissmissable: true,
            title: "Delete attendee",
            $footerContent: modalCancel().add(
              $(
                `<button class="lookFilled colorRed" tabindex="-1">Delete attendee</button>`
              ).click(() => {
                deleteAttendee();
                closeModal();
              })
            ),
          });
          $(".modalContentBody").html(
            `Are you sure you want to delete <b>${$elem.username}</b>?`
          );
        })
      );

    if (initSettings) {
      $usernameInput.val(initSettings.username);
      $rankInput.setOption(initSettings.rank);
      $resultInput.setOption(initSettings.result);
      if (initSettings.award) $awardInput.setValue(initSettings.award);
      if (initSettings.notes) $elem.notes = initSettings.notes;
    }

    function focus() {
      $usernameInput.focus();
    }

    function insertActivity(score, editHandler) {
      const $insertedTd = $(`<td>
				<div class="tdRow">
					<div class="score"><b>${score[0]}</b>/${score[1]}</div>
				</div>
			</td>`);

      function updateScore(score) {
        $insertedTd.find(".score b").text(score[0]);
        $insertedTd.find(".score").contents().eq(1).replaceWith(`/${score[1]}`);
      }

      $insertedTd
        .find(".tdRow")
        .append(
          $(
            `<button class="lookFilled colorWhite attendeeActivityGrading" tabindex="-1"><i class="fas fa-edit"></i></button>`
          ).click(() => editHandler(id))
        );
      $insertedTd.insertBefore($placeHolderTd);

      Object.assign($insertedTd, {
        updateScore,
      });

      return $insertedTd;
    }

    function hasPassed() {
      if (!activities.size) return null;
      const score = getScore();
      let requiredscoretopass = 0;

      if ($typeSelect.value == 1) {
        requiredscoretopass = 7;
      } else if ($typeSelect.value == 3) {
        if ($rankInput.value == 1) {
          requiredscoretopass = 12;
        } else if ($rankInput.value == 2) {
          requiredscoretopass = 13;
        } else if ($rankInput.value == 3) {
          requiredscoretopass = 13.5;
        } else {
          requiredscoretopass = 13.5;
        }
      } else if ($typeSelect.value == 5) {
        const openQuestions = activities.find(
          (activity) => activity.name === "Open Questions"
        );
        const situationalQuestions = activities.find(
          (activity) => activity.name === "Situational Questions"
        );

        if (openQuestions && situationalQuestions) {
          const openScore = openQuestions.getAttendeeScore(id)[0];
          const situationalScore = situationalQuestions.getAttendeeScore(id)[0];

          return openScore === 4 && situationalScore >= 1;
        }
        return false;
      }

      return score[0] >= requiredscoretopass;
    }


    function updateScore() {
      const score = getScore();
      const score100 = getScore100();
      const passed = hasPassed();

      $elem.find("td.score b").eq(0).text(score[0]);
      $elem.find("td.score").eq(0).contents().eq(1).replaceWith(`/${score[1]}`);
      $elem.find("td.score b").eq(1).text(score100);

      const $score100e = $elem.find("td.score").eq(1);
      if (passed === false)
        $score100e.addClass("scoreFailed").removeClass("scorePassed");
      else if (passed === null)
        $score100e.removeClass("scoreFailed scorePassed");
      else if (passed === true)
        $score100e.addClass("scorePassed").removeClass("scoreFailed");
    }

    function getScore() {
      const score = activities.reduce(
        (acc, activity) => {
          const activityScore = activity.getAttendeeScore(id);
          acc[0] += (activityScore[0] / activityScore[1]) * activity.totalMarks;
          if (!activity.bonus) acc[1] += activity.totalMarks;
          return acc;
        },
        [0, 0]
      );
      score[0] = Math.min(Math.round(score[0] * 100) / 100, score[1]);
      return score;
    }

    function getScore100() {
      const score = getScore();
      return score[1]
        ? Math.round(((score[0] + Number.EPSILON) * 100) / score[1])
        : 0;
    }

    function getScore1000() {
      const score = getScore();
      return score[1]
        ? Math.round(((score[0] + Number.EPSILON) * 1000) / score[1])
        : 0;
    }

    function deleteAttendee() {
      attendees.delete(id);
      activities.forEach((activity) => {
        activity.attendees.delete(id);
        activity.tds.delete(id);
      });
      $elem.remove();
      updateAttendeeCounter();
      updateAttendeeIndexes();
    }

    $(".attendees tbody").append($elem);
    updateAttendeeIndexes();

    Object.assign($elem, {
      id,
      index,
      focus,
      insertActivity,
      updateScore,
      getScore,
      getScore100,
      hasPassed,
      $resultInput,
      $usernameInput,
      deleteAttendee,
    });

    activities.forEach((activity) => {
      activity.attendees.set(id, activity.defaultAttendee());
      activity.tdHandler($elem, id);
    });

    updateScore();

    Object.defineProperties($elem, {
      username: {
        get: () => $usernameInput.val() || "Unamed attendee",
      },
      rank: {
        get: () => $rankInput.value,
      },
      result: {
        get: () => $resultInput.value,
      },
      award: {
        get: () => $awardInput.value,
      },
    });

    attendees.set(id, $elem);
    updateAttendeeCounter();

    return $elem;
  }

  $(".attendees th")
    .eq(4)
    .append(
      dropdown(
        new Collection()
          .set(0, {
            name: "Guidelines questions",
            cb: () => {
              openModal({
                modalClass: "sizeMedium",
                title: `New activity: ${activityTypes.get(1)}`,
                bodyClass: "modalForm",
                $footerContent: modalCancel().add(
                  $(
                    `<button class="lookFilled colorWhite widthFitContent" tabindex="-1">Create activity</button>`
                  ).click(submit)
                ),
              });

              const { questions, $totalMarksInput, addQuestion } =
                guidelinesQuestionsSettingsModalBody(submit);
              addQuestion().focus();

              function submit() {
                if (
                  !questions.every(
                    (question) =>
                      question.$questionInput.isValid() &&
                      question.$answerInput.isValid()
                  ) ||
                  !$totalMarksInput.isValid()
                )
                  return;

                guidelinesQuestions({
                  questions: questions.mapValues((question) => ({
                    question: question.$questionInput.val().trim(),
                    answer: question.$answerInput.val().trim(),
                  })),
                  totalMarks: Number($totalMarksInput.val()),
                });

                closeModal();
              }
            },
          })
          .set(1, {
            name: "Multi activity",
            cb: () => {
              function submit() {
                if (
                  !$nameInput.isValid() ||
                  !items.every(($input) => $input.isValid()) ||
                  !$itemMarkingSchemeInput.isValid() ||
                  !$totalMarksInput.isValid()
                )
                  return;

                multiActivity({
                  name: $nameInput.val().trim(),
                  items: items.mapValues(($input) => $input.val().trim()),
                  itemMarkingScheme: Number($itemMarkingSchemeInput.val()),
                  totalMarks: Number($totalMarksInput.val()),
                });

                closeModal();
              }

              openModal({
                title: `New activity: ${activityTypes.get(2)}`,
                bodyClass: "modalForm",
                $footerContent: modalCancel().add(
                  $(
                    `<button class="lookFilled colorWhite widthFitContent" tabindex="-1">Create activity</button>`
                  ).click(submit)
                ),
              });

              const {
                $nameInput,
                items,
                $itemMarkingSchemeInput,
                $totalMarksInput,
                addItem,
              } = multiActivitySettingsModalBody(submit);
              $nameInput.focus();
              addItem();
            },
          })
          .set(2, {
            name: "Simple activity",
            cb: () => {
              function submit() {
                if (
                  !$nameInput.isValid() ||
                  !$markingSchemeInput.isValid() ||
                  !$totalMarksInput.isValid()
                )
                  return;

                simpleActivity({
                  name: $nameInput.val().trim(),
                  markingScheme: Number($markingSchemeInput.val()),
                  totalMarks: Number($totalMarksInput.val()),
                  bonus: $bonusInput.value,
                });

                closeModal();
              }

              openModal({
                title: `New activity: ${activityTypes.get(3)}`,
                bodyClass: "modalForm",
                $footerContent: modalCancel().add(
                  $(
                    `<button class="lookFilled colorWhite widthFitContent" tabindex="-1">Create activity</button>`
                  ).click(submit)
                ),
              });

              const {
                $nameInput,
                $markingSchemeInput,
                $totalMarksInput,
                $bonusInput,
              } = simpleActivitySettingsModalBody(submit);
              $nameInput.focus();
            },
          }),
        {
          $button: $(
            `<button class="lookFilled colorWhite" tabindex="-1"><i class="fas fa-folder-plus marginRight4"></i> New Activity</button>`
          ),
          $popoutContainer: $(".tablePopoutsContainer"),
        }
      ).addClass("newActivityButton")
    );

  function guidelinesQuestionsSettingsModalBody(submit) {
    const questions = new Collection();

    const $addButton = $(
      `<button class="lookFilled colorGreen" tabindex="-1"><i class="fas fa-plus"></i></button>`
    ).click(() => addQuestion().focus()),
      $totalMarksInput = input({
        inputClass: "input smallInput",
        validator: (val) => /^\d+(\.\d)?$/.test(val) && Number(val),
        enter: submit,
        value: 3,
      });

    $(".modalContentBody")
      .append($addButton)
      .append(
        $(`<div class="formField marginTopSmall">
			<span class="fieldName">Total marks:</span>
		</div>`).append($totalMarksInput)
      );

    function addQuestion(
      question,
      answer,
      questionID = AUTO_INCREMENT++,
      deletion
    ) {
      const $elem = $(
        `<div class="marginBottomSmall"><h4 class="modalH4 white textCenter size16 height20 weightSemiBold marginBottomSmall">Question ${questions.size + 1
        }</h4><div class="flex"><div class="flexGrow"></div></div></div>`
      ),
        $questionInput = input({
          value: question,
          validator: (val) => val.trim(),
          enter: submit,
        }),
        $answerInput = input({
          value: answer,
          validator: (val) => val.trim(),
          enter: submit,
          shiftEnter: () => addQuestion().focus(),
        });

      $elem
        .find("div div")
        .append(
          $(`<div class="formField">
				<span class="fieldName flexGrow">Question:</span>
			</div>`).append($questionInput)
        )
        .append(
          $(`<div class="formField">
				<span class="fieldName flexGrow">Answer:</span>
			</div>`).append($answerInput)
        );

      $elem.find(".flex").append(
        $(
          `<button class="ghostButton questionDelete" tabindex="-1"><i class="fas fa-times-circle"></i></button>`
        ).click(() => {
          if (questions.size < 2) return;

          $elem.remove();
          questions.delete(questionID);

          if (deletion) deletion();

          questions.forEach((question) => question.updateNumber());
        })
      );

      questions.set(questionID, {
        $questionInput,
        $answerInput,
        updateNumber: () =>
          $elem
            .find("h4")
            .text(`Question ${questions.keyArray().indexOf(questionID) + 1}`),
      });

      $addButton.before($elem);

      return $questionInput;
    }

    return { $totalMarksInput, questions, addQuestion };
  }

  function guidelinesQuestions(initSettings, noWentOver) {
    const id = AUTO_INCREMENT++;
    const activity = {
      type: 1,
      name: activityTypes.get(1),
      totalMarks: initSettings.totalMarks,
      attendees:
        initSettings.attendees ||
        new Collection(
          attendees
            .keyArray()
            .map((attendeeID) => [attendeeID, defaultAttendee()])
        ),
      questions: initSettings.questions,
      tds: new Collection(),
      currentTab: 0,
      defaultAttendee,
      tdHandler: (attendee, attendeeID) =>
        activity.tds.set(
          attendeeID,
          attendee.insertActivity(
            getAttendeeScore(attendeeID),
            attendeeGradingModal
          )
        ),
    };

    const $tdHead = $(`<th>
			<div class="tdRow">
				<span class="activityName">${activity.name}</span>
			</div>
		</th>`);
    $tdHead
      .find(".tdRow")
      .append(
        $(`<button class="lookFilled colorWhite activityGrading" tabindex="-1">
			<i class="fas fa-edit"></i>
		</button>`).click(gradingModal)
      )
      .append(
        $(`<button class="lookFilled colorWhite activitySettings" tabindex="-1">
			<i class="fas fa-cog"></i>
		</button>`).click(settingsModal)
      );

    attendees.forEach(activity.tdHandler);

    $(".newActivity").before($tdHead);

    if (!noWentOver) appendWentOver(activity.name);

    function defaultAttendee() {
      return new Collection();
    }

    function getMarkingScheme() {
      return activity.questions.size;
    }

    function getAttendeeScore(attendeeID) {
      return [
        activity.attendees
          .get(attendeeID)
          .reduce((acc, question) => acc + questionsMarks.get(question), 0),
        getMarkingScheme(),
      ];
    }

    function deleteModal() {
      openModal({
        title: "Delete activity",
        backdropDissmissable: true,
        $footerContent: modalCancel(settingsModal).add(
          $(
            `<button class="lookFilled colorRed" tabindex="-1">Delete activity</button>`
          ).click(() => {
            deleteActivity();
            closeModal();
          })
        ),
      });
      $(".modalContentBody").html(
        `Are you sure you want to delete <b>${activity.name}</b>?`
      );
    }

    function settingsModal() {
      openModal({
        title: `Edit ${activity.name}`,
        modalClass: "sizeMedium",
        bodyClass: "modalForm",
        $footerContent: $(
          `<button class="lookFilled colorRed marginRightAuto" tabindex="-1">Delete activity</button>`
        )
          .click(deleteModal)
          .add(modalCancel())
          .add(
            $(
              `<button class="lookFilled colorWhite" tabindex="-1">Save</button>`
            ).click(submit)
          ),
      });

      const { questions, $totalMarksInput, addQuestion } =
        guidelinesQuestionsSettingsModalBody(submit);

      const toDelete = new Set();

      activity.questions.forEach((question, questionID) =>
        addQuestion(question.question, question.answer, questionID, () =>
          toDelete.add(questionID)
        )
      );

      function submit() {
        if (
          !questions.every(
            (question) =>
              question.$questionInput.isValid() &&
              question.$answerInput.isValid()
          ) ||
          !$totalMarksInput.isValid()
        )
          return;

        toDelete.forEach((questionID) =>
          activity.attendees.forEach((questions) =>
            questions.delete(questionID)
          )
        );

        activity.questions = questions.mapValues((question) => ({
          question: question.$questionInput.val().trim(),
          answer: question.$answerInput.val().trim(),
        }));
        activity.totalMarks = Number($totalMarksInput.val());
        activity.tds.forEach(($td, attendeeID) =>
          $td.updateScore(getAttendeeScore(attendeeID))
        );
        attendees.forEach((attendee) => attendee.updateScore());

        closeModal();
      }

      $totalMarksInput.val(activity.totalMarks);
    }

    function gradingModal() {
      openModal({
        title: `Grade ${activity.name}`,
        headerClass: "multi",
        bodyClass: "modalForm",
        $footerContent: modalCancel().add(
          $(
            `<button class="lookFilled colorWhite" tabindex="-1">Save</button>`
          ).click(submit)
        ),
      });

      let currentItem;
      const items = activity.questions.keyArray();

      const $modalMulti =
        $(`<div class="flex directionRow justifySpaceBetween alignCenter noWrap modalMulti">
				<h4 class="modalH4 modalTitle size16 height20 weightSemiBold white modalHeaderTitle textCenter"></h4>
			</div>`)
          .prepend(
            $(`<button class="modalMultiSwitch" tabindex="-1">
				<i class="fas fa-chevron-left"></i>
			</button>`).click(() => {
              if (currentItem > 0) modalGradeContent(currentItem - 1);
            })
          )
          .append(
            $(`<button class="modalMultiSwitch" tabindex="-1">
				<i class="fas fa-chevron-right"></i>
			</button>`).click(() => {
              if (currentItem < items.length - 1)
                modalGradeContent(currentItem + 1);
            })
          );

      const scores = new Collection();

      function modalGradeContent(item) {
        currentItem = item;
        activity.currentTab = item;
        $modalMulti
          .find(".modalTitle")
          .text(
            `Question ${activity.questions.keyArray().indexOf(items[item]) + 1}`
          );

        scores.forEach((questions) =>
          questions.forEach(($input) => $input.detach())
        );

        $(".modalContentBody")
          .empty()
          .append(
            `<div class="flex directionColumn marginBottomSmall"><span class="flexGrow textCenter white weightSemiBold marginBottom8 selectable">${activity.questions.get(items[item]).question
            }</span><span class="flexGrow textCenter selectable">${activity.questions.get(items[item]).answer
            }</span></div>`
          );

        attendees
          .filter((attendee) => ![3, 4, 8].includes(attendee.result))
          .sort((a, b) => a.index - b.index)
          .forEach((attendee, attendeeID) => {
            const $scoreInput =
              scores.has(attendeeID) && scores.get(attendeeID).has(items[item])
                ? scores.get(attendeeID).get(items[item])
                : markInput().setValue(
                  activity.attendees.get(attendeeID).get(items[item])
                );

            $(".modalContentBody").append(
              $(`<div class="formField">
						<span class="fieldName">${attendee.username}:</span>
					</div>`).append($scoreInput)
            );

            if (!scores.has(attendeeID))
              scores.set(attendeeID, new Collection());
            if (!scores.get(attendeeID).has(items[item]))
              scores.get(attendeeID).set(items[item], $scoreInput);
          });
      }

      function submit() {
        scores.forEach((questions, attendeeID) =>
          questions.forEach(($input, questionID) =>
            activity.attendees.get(attendeeID).set(questionID, $input.value)
          )
        );

        activity.tds.forEach(($td, attendeeID) =>
          $td.updateScore(getAttendeeScore(attendeeID))
        );
        attendees.forEach((attendee) => attendee.updateScore());

        closeModal();
      }

      $(".modalHeader").after($modalMulti);

      modalGradeContent(
        Math.min(activity.currentTab, activity.questions.size - 1)
      );
    }

    function attendeeGradingModal(attendeeID) {
      openModal({
        title: `${activity.name}: ${attendees.get(attendeeID).username
          }'s grade`,
        bodyClass: "modalForm",
        $footerContent: modalCancel().add(
          $(
            `<button class="lookFilled colorWhite" tabindex="-1">Save</button>`
          ).click(() => {
            scores.forEach(($input, questionID) =>
              activity.attendees.get(attendeeID).set(questionID, $input.value)
            );

            activity.tds
              .get(attendeeID)
              .updateScore(getAttendeeScore(attendeeID));
            attendees.get(attendeeID).updateScore();

            closeModal();
          })
        ),
      });

      const scores = new Collection();

      activity.questions.forEach((question, questionID) => {
        const $input = markInput().setValue(
          activity.attendees.get(attendeeID).get(questionID)
        );

        $(".modalContentBody").append(
          $(`<div class="formField">
					<span class="fieldName">Question ${activity.questions.keyArray().indexOf(questionID) + 1
            }:</span>
				</div>`).append($input)
        );

        scores.set(questionID, $input);
      });
    }

    function deleteActivity() {
      $tdHead.remove();
      activity.tds.forEach(($td) => $td.remove());
      activities.delete(id);
      attendees.forEach((attendee) => attendee.updateScore());
    }

    Object.assign(activity, {
      getAttendeeScore,
      deleteActivity,
    });

    activities.set(id, activity);

    attendees.forEach((attendee) => attendee.updateScore());

    return activity;
  }

  function multiActivitySettingsModalBody(submit) {
    const items = new Collection();

    const $nameInput = input({
      validator: (val) => val.trim(),
      enter: submit,
    }),
      $addButton = $(
        `<button class="lookFilled colorGreen" tabindex="-1"><i class="fas fa-plus"></i></button>`
      ).click(() => addItem().focus()),
      $itemMarkingSchemeInput = input({
        inputClass: "input inputOn smallInput",
        enter: submit,
        validator: (val) => /^\d+(\.\d)?$/.test(val) && Number(val),
        value: 1,
      }),
      $totalMarksInput = input({
        inputClass: "input smallInput",
        validator: (val) => /^\d+(\.\d)?$/.test(val) && Number(val),
        enter: submit,
        value: 3,
      });

    $(".modalContentBody")
      .append(
        $(`<div class="formField">
			<span class="fieldName flexGrow">Name:</span>
		</div>`).append($nameInput)
      )
      .append(
        `<h4 class="modalH4 white textCenter size16 height20 weightSemiBold marginBottomSmall marginTopSmall">Items</h4>`
      )
      .append($addButton)
      .append(
        $(`<div class="formField marginTopSmall">
			<span class="fieldName">Item marking scheme:</span>
		</div>`).append($itemMarkingSchemeInput)
      )
      .append(
        $(`<div class="formField">
			<span class="fieldName">Total marks:</span>
		</div>`).append($totalMarksInput)
      );

    function addItem(item, itemID = AUTO_INCREMENT++, deletion) {
      const $elem = $(`<div class="marginBottom8 flex"></div>`),
        $itemInput = input({
          value: item,
          validator: (val) => val.trim(),
          enter: submit,
          shiftEnter: () => addItem().focus(),
        });

      $elem.append($itemInput);

      $elem.append(
        $(
          `<button class="ghostButton itemDelete" tabindex="-1"><i class="fas fa-times-circle"></i></button>`
        ).click(() => {
          if (items.size < 2) return;

          $elem.remove();
          items.delete(itemID);

          if (deletion) deletion();
        })
      );

      items.set(itemID, $itemInput);

      $addButton.before($elem);

      return $itemInput;
    }

    return {
      $nameInput,
      items,
      $itemMarkingSchemeInput,
      $totalMarksInput,
      addItem,
    };
  }

  function multiActivity(initSettings, noWentOver) {
    const id = AUTO_INCREMENT++;
    const activity = {
      type: 2,
      name: initSettings.name,
      totalMarks: initSettings.totalMarks,
      attendees:
        initSettings.attendees ||
        new Collection(
          attendees
            .keyArray()
            .map((attendeeID) => [attendeeID, defaultAttendee()])
        ),
      items: initSettings.items,
      itemMarkingScheme: initSettings.itemMarkingScheme,
      tds: new Collection(),
      currentTab: 0,
      defaultAttendee,
      tdHandler: (attendee, attendeeID) =>
        activity.tds.set(
          attendeeID,
          attendee.insertActivity(
            getAttendeeScore(attendeeID),
            attendeeGradingModal
          )
        ),
    };

    const $tdHead = $(`<th>
			<div class="tdRow">
				<span class="activityName">${activity.name}</span>
			</div>
		</th>`);
    $tdHead
      .find(".tdRow")
      .append(
        $(`<button class="lookFilled colorWhite activityGrading" tabindex="-1">
			<i class="fas fa-edit"></i>
		</button>`).click(gradingModal)
      )
      .append(
        $(`<button class="lookFilled colorWhite activitySettings" tabindex="-1">
			<i class="fas fa-cog"></i>
		</button>`).click(settingsModal)
      );

    attendees.forEach(activity.tdHandler);

    $(".newActivity").before($tdHead);

    if (!noWentOver) appendWentOver(activity.name);

    function defaultAttendee() {
      return new Collection();
    }

    function getMarkingScheme() {
      return activity.items.size * activity.itemMarkingScheme;
    }

    function getAttendeeScore(attendeeID) {
      return [
        activity.attendees
          .get(attendeeID)
          .reduce((acc, score) => acc + score, 0),
        getMarkingScheme(),
      ];
    }

    function deleteModal() {
      openModal({
        title: "Delete activity",
        backdropDissmissable: true,
        $footerContent: modalCancel(settingsModal).add(
          $(
            `<button class="lookFilled colorRed" tabindex="-1">Delete activity</button>`
          ).click(() => {
            deleteActivity();
            closeModal();
          })
        ),
      });
      $(".modalContentBody").html(
        `Are you sure you want to delete <b>${activity.name}</b>?`
      );
    }

    function settingsModal() {
      openModal({
        title: `Edit ${activity.name}`,
        bodyClass: "modalForm",
        $footerContent: $(
          `<button class="lookFilled colorRed marginRightAuto" tabindex="-1">Delete activity</button>`
        )
          .click(deleteModal)
          .add(modalCancel())
          .add(
            $(
              `<button class="lookFilled colorWhite" tabindex="-1">Save</button>`
            ).click(submit)
          ),
      });

      const {
        $nameInput,
        items,
        $itemMarkingSchemeInput,
        $totalMarksInput,
        addItem,
      } = multiActivitySettingsModalBody(submit);

      const toDelete = new Set();

      activity.items.forEach((item, itemID) =>
        addItem(item, itemID, () => toDelete.add(itemID))
      );

      function submit() {
        if (
          !$nameInput.isValid() ||
          !items.every(($input) => $input.isValid()) ||
          !$itemMarkingSchemeInput.isValid() ||
          !$totalMarksInput.isValid()
        )
          return;

        toDelete.forEach((itemID) =>
          activity.attendees.forEach((attendee) => attendee.delete(itemID))
        );

        activity.name = $nameInput.val().trim();
        $tdHead.find(".activityName").text(activity.name);
        activity.items = items.mapValues(($input) => $input.val().trim());
        activity.itemMarkingScheme = Number($itemMarkingSchemeInput.val());
        activity.totalMarks = Number($totalMarksInput.val());

        activity.tds.forEach(($td, attendeeID) =>
          $td.updateScore(getAttendeeScore(attendeeID))
        );
        attendees.forEach((attendee) => attendee.updateScore());

        closeModal();
      }

      $nameInput.val(activity.name);
      $itemMarkingSchemeInput
        .val(activity.itemMarkingScheme)
        .setValidator(
          (val) =>
            /^\d+(\.\d)?$/.test(val) &&
            Number(val) &&
            !activity.attendees.some((items) =>
              items.some((grade) => grade > val)
            )
        );
      $totalMarksInput.val(activity.totalMarks);
    }

    function gradingModal() {
      openModal({
        title: `Grade ${activity.name}`,
        headerClass: "multi",
        bodyClass: "modalForm",
        $footerContent: modalCancel().add(
          $(
            `<button class="lookFilled colorWhite" tabindex="-1">Save</button>`
          ).click(submit)
        ),
      });

      let currentItem;
      const items = activity.items.keyArray();

      const $modalMulti =
        $(`<div class="flex directionRow justifySpaceBetween alignCenter noWrap modalMulti">
				<h4 class="modalH4 modalTitle size16 height20 weightSemiBold white modalHeaderTitle textCenter"></h4>
			</div>`)
          .prepend(
            $(`<button class="modalMultiSwitch" tabindex="-1">
				<i class="fas fa-chevron-left"></i>
			</button>`).click(() => {
              if (currentItem > 0) modalGradeContent(currentItem - 1);
            })
          )
          .append(
            $(`<button class="modalMultiSwitch" tabindex="-1">
				<i class="fas fa-chevron-right"></i>
			</button>`).click(() => {
              if (currentItem < items.length - 1)
                modalGradeContent(currentItem + 1);
            })
          )
          .insertAfter(".modalHeader");

      const scores = new Collection();

      function submit() {
        if (!scores.every((items) => items.every(($input) => $input.isValid())))
          return;

        scores.forEach((items, attendeeID) =>
          items.forEach(($input, itemID) =>
            activity.attendees.get(attendeeID).set(itemID, Number($input.val()))
          )
        );

        activity.tds.forEach(($td, attendeeID) =>
          $td.updateScore(getAttendeeScore(attendeeID))
        );
        attendees.forEach((attendee) => attendee.updateScore());

        closeModal();
      }

      function modalGradeContent(item) {
        currentItem = item;
        activity.currentTab = item;
        $modalMulti.find(".modalTitle").text(activity.items.get(items[item]));

        scores.forEach((items) => items.forEach(($input) => $input.detach()));

        $(".modalContentBody").empty();

        attendees
          .filter((attendee) => ![3, 4, 8].includes(attendee.result))
          .sort((a, b) => a.index - b.index)
          .forEach((attendee, attendeeID, i) => {
            const $scoreInput =
              scores.has(attendeeID) && scores.get(attendeeID).has(items[item])
                ? scores.get(attendeeID).get(items[item])
                : input({
                  inputClass: "input inputOf smallInput",
                  validator: (val) =>
                    /^\d+(\.\d{1,2})?$/.test(val) &&
                    val <= activity.itemMarkingScheme,
                  value:
                    activity.attendees.get(attendeeID).get(items[item]) || 0,
                  enter: submit,
                });

            $(".modalContentBody").append(
              $(`<div class="formField">
						<span class="fieldName">${attendee.username}:</span>
					</div>`)
                .append($scoreInput)
                .append(`/${activity.itemMarkingScheme}`)
            );
            if (i === 0) $scoreInput.select();

            if (!scores.has(attendeeID))
              scores.set(attendeeID, new Collection());
            if (!scores.get(attendeeID).has(items[item]))
              scores.get(attendeeID).set(items[item], $scoreInput);
          });
      }

      modalGradeContent(Math.min(activity.currentTab, activity.items.size - 1));
    }

    function attendeeGradingModal(attendeeID) {
      openModal({
        title: `${activity.name}: ${attendees.get(attendeeID).username
          }'s grade`,
        bodyClass: "modalForm",
        $footerContent: modalCancel().add(
          $(
            `<button class="lookFilled colorWhite" tabindex="-1">Save</button>`
          ).click(submit)
        ),
      });

      const scores = new Collection();

      function submit() {
        if (!scores.every(($input) => $input.isValid())) return;

        scores.forEach(($input, itemID) =>
          activity.attendees.get(attendeeID).set(itemID, Number($input.val()))
        );

        activity.tds.get(attendeeID).updateScore(getAttendeeScore(attendeeID));
        attendees.get(attendeeID).updateScore();

        closeModal();
      }

      activity.items.forEach((item, itemID, i) => {
        const $input = input({
          inputClass: "input inputOf smallInput",
          validator: (val) =>
            /^\d+(\.\d{1,2})?$/.test(val) && val <= activity.itemMarkingScheme,
          value: activity.attendees.get(attendeeID).get(itemID) || 0,
          enter: submit,
        });

        $(".modalContentBody").append(
          $(`<div class="formField">
					<span class="fieldName">${activity.items.get(itemID)}:</span>
				</div>`)
            .append($input)
            .append(`/${activity.itemMarkingScheme}`)
        );
        if (i === 0) $input.select();

        scores.set(itemID, $input);
      });
    }

    function deleteActivity() {
      $tdHead.remove();
      activity.tds.forEach(($td) => $td.remove());
      activities.delete(id);
      attendees.forEach((attendee) => attendee.updateScore());
    }

    Object.assign(activity, {
      getAttendeeScore,
      deleteActivity,
    });

    activities.set(id, activity);

    attendees.forEach((attendee) => attendee.updateScore());

    return activity;
  }

  function simpleActivitySettingsModalBody(submit) {
    const $nameInput = input({
      validator: (val) => val.trim(),
      enter: submit,
    }),
      $markingSchemeInput = input({
        inputClass: "input inputOn smallInput",
        enter: submit,
        validator: (val) => /^\d+(\.\d)?$/.test(val) && Number(val),
      }),
      $totalMarksInput = input({
        inputClass: "input smallInput",
        validator: (val) => /^\d+(\.\d)?$/.test(val) && Number(val),
        enter: submit,
        value: 3,
      }),
      $bonusInput = checkbox();

    $(".modalContentBody")
      .append(
        $(`<div class="formField">
			<span class="fieldName">Activity name:</span>
		</div>`).append($nameInput)
      )
      .append(
        $(`<div class="formField">
			<span class="fieldName">Marking scheme:</span>/
		</div>`).append($markingSchemeInput)
      )
      .append(
        $(`<div class="formField">
			<span class="fieldName">Total marks:</span>
		</div>`).append($totalMarksInput)
      )
      .append(
        $(`<div class="formField">
			<span class="fieldName">Bonus:</span>
		</div>`).append($bonusInput)
      );

    return {
      $nameInput,
      $markingSchemeInput,
      $totalMarksInput,
      $bonusInput,
    };
  }

  function simpleActivity(initSettings, noWentOver = false) {
    const id = AUTO_INCREMENT++;
    const activity = {
      type: 3,
      name: initSettings.name,
      markingScheme: initSettings.markingScheme,
      totalMarks: initSettings.totalMarks,
      bonus: initSettings.bonus,
      attendees:
        initSettings.attendees ||
        new Collection(
          attendees
            .keyArray()
            .map((attendeeID) => [attendeeID, defaultAttendee()])
        ),
      tds: new Collection(),
      defaultAttendee,
      tdHandler: (attendee, attendeeID) =>
        activity.tds.set(
          attendeeID,
          attendee.insertActivity(
            getAttendeeScore(attendeeID),
            attendeeGradingModal
          )
        ),
    };

    const $tdHead = $(`<th>
			<div class="tdRow">
				<span class="activityName">${activity.name}</span>
			</div>
		</th>`);
    $tdHead
      .find(".tdRow")
      .append(
        $(`<button class="lookFilled colorWhite activityGrading" tabindex="-1">
			<i class="fas fa-edit"></i>
		</button>`).click(gradingModal)
      )
      .append(
        $(`<button class="lookFilled colorWhite activitySettings" tabindex="-1">
			<i class="fas fa-cog"></i>
		</button>`).click(settingsModal)
      );

    attendees.forEach(activity.tdHandler);

    if (!noWentOver) appendWentOver(activity.name);

    $(".newActivity").before($tdHead);

    function defaultAttendee() {
      return 0;
    }

    function getMarkingScheme() {
      return activity.markingScheme;
    }

    function getAttendeeScore(attendeeID) {
      return [activity.attendees.get(attendeeID), getMarkingScheme()];
    }

    function deleteModal() {
      openModal({
        title: "Delete activity",
        backdropDissmissable: true,
        $footerContent: modalCancel(settingsModal).add(
          $(
            `<button class="lookFilled colorRed" tabindex="-1">Delete activity</button>`
          ).click(() => {
            deleteActivity();
            closeModal();
          })
        ),
      });
      $(".modalContentBody").html(
        `Are you sure you want to delete <b>${activity.name}</b>?`
      );
    }

    function settingsModal() {
      openModal({
        title: `Edit ${activity.name}`,
        bodyClass: "modalForm",
        $footerContent: $(
          `<button class="lookFilled colorRed marginRightAuto" tabindex="-1">Delete activity</button>`
        )
          .click(deleteModal)
          .add(modalCancel())
          .add(
            $(
              `<button class="lookFilled colorWhite" tabindex="-1">Save</button>`
            ).click(submit)
          ),
      });

      const { $nameInput, $markingSchemeInput, $totalMarksInput, $bonusInput } =
        simpleActivitySettingsModalBody(submit);

      $nameInput.val(activity.name);
      $markingSchemeInput
        .val(activity.markingScheme)
        .setValidator(
          (val) =>
            /^\d+(\.\d)?$/.test(val) &&
            Number(val) &&
            !activity.attendees.some((grade) => grade > val)
        );
      $totalMarksInput.val(activity.totalMarks);
      if (activity.bonus) $bonusInput.check();

      function submit() {
        if (
          !$nameInput.isValid() ||
          !$markingSchemeInput.isValid() ||
          !$totalMarksInput.isValid()
        )
          return;

        activity.name = $nameInput.val().trim();
        $tdHead.find(".activityName").text(activity.name);
        activity.markingScheme = Number($markingSchemeInput.val());
        activity.totalMarks = Number($totalMarksInput.val());
        activity.bonus = $bonusInput.value;

        activity.tds.forEach(($td, attendeeID) =>
          $td.updateScore(getAttendeeScore(attendeeID))
        );
        attendees.forEach((attendee) => attendee.updateScore());

        closeModal();
      }
    }

    function gradingModal() {
      openModal({
        title: `Grade ${activity.name}`,
        bodyClass: "modalForm",
        $footerContent: modalCancel().add(
          $(
            `<button class="lookFilled colorWhite" tabindex="-1">Save</button>`
          ).click(submit)
        ),
      });

      const scores = new Collection();

      function submit() {
        if (!scores.every(($input) => $input.isValid())) return;

        scores.forEach(($input, attendeeID) =>
          activity.attendees.set(attendeeID, Number($input.val()))
        );

        activity.tds.forEach(($td, attendeeID) =>
          $td.updateScore(getAttendeeScore(attendeeID))
        );
        attendees.forEach((attendee) => attendee.updateScore());

        closeModal();
      }

      attendees
        .filter((attendee) => ![3, 4, 8].includes(attendee.result))
        .sort((a, b) => a.index - b.index)
        .forEach((attendee, attendeeID, i) => {
          const $scoreInput = input({
            inputClass: "input inputOf smallInput",
            validator: (val) =>
              /^\d+(\.\d{1,2})?$/.test(val) && val <= activity.markingScheme,
            value: activity.attendees.get(attendeeID),
            enter: submit,
          });

          $(".modalContentBody").append(
            $(`<div class="formField">
					<span class="fieldName">${attendee.username}:</span>
				</div>`)
              .append($scoreInput)
              .append(`/${getMarkingScheme()}`)
          );

          if (i === 0) $scoreInput.select();

          scores.set(attendeeID, $scoreInput);
        });
    }

    function attendeeGradingModal(attendeeID) {
      openModal({
        title: `${activity.name}: ${attendees.get(attendeeID).username
          }'s grade`,
        bodyClass: "modalForm",
        $footerContent: modalCancel().add(
          $(
            `<button class="lookFilled colorWhite" tabindex="-1">Save</button>`
          ).click(submit)
        ),
      });

      function submit() {
        if (!$scoreInput.isValid()) return;

        activity.attendees.set(attendeeID, Number($scoreInput.val()));

        activity.tds.get(attendeeID).updateScore(getAttendeeScore(attendeeID));
        attendees.get(attendeeID).updateScore();

        closeModal();
      }

      const $scoreInput = input({
        inputClass: "input inputOf smallInput",
        validator: (val) =>
          /^\d+(\.\d{1,2})?$/.test(val) && val <= activity.markingScheme,
        value: activity.attendees.get(attendeeID),
        enter: submit,
      });

      $(".modalContentBody").append(
        $(`<div class="formField">
				<span class="fieldName">Score:</span>
			</div>`)
          .append($scoreInput)
          .append(`/${activity.markingScheme}`)
      );

      $scoreInput.select();
    }

    function deleteActivity() {
      $tdHead.remove();
      activity.tds.forEach(($td) => $td.remove());
      activities.delete(id);
      attendees.forEach((attendee) => attendee.updateScore());
    }

    Object.assign(activity, {
      getAttendeeScore,
      deleteActivity,
    });

    activities.set(id, activity);

    attendees.forEach((attendee) => attendee.updateScore());

    return activity;
  }

  function getTrainingObject() {
    return {
      type: $typeSelect.value,
      coHosts: coHosts.map((coHost) => coHost.username),
      spectators: spectators.map((spectator) => spectator.username),
      wentOver: $wentOverInput.val(),
      notes: $notesInput.val(),
      date: $dateInput.val(),
      attendees: attendees
        .sort((a, b) => a.index - b.index)
        .map(({ $usernameInput, rank, result, award, notes }) => ({
          username: $usernameInput.val(),
          rank,
          result,
          award,
          notes,
        })),
      activities: activities.map((activity) => {
        const val = {
          type: activity.type,
          name: activity.name,
          totalMarks: activity.totalMarks,
        };
        if (activity.type === 1) {
          val.questions = activity.questions.array();
          val.attendees = activity.attendees.map((grade) => grade.array());
        } else if (activity.type === 2) {
          val.items = activity.items.array();
          val.itemMarkingScheme = activity.itemMarkingScheme;
          val.attendees = activity.attendees.map((grade) => grade.array());
        } else if (activity.type === 3) {
          val.markingScheme = activity.markingScheme;
          val.bonus = activity.bonus;
          val.attendees = activity.attendees.array();
        }
        return val;
      }),
    };
  }

  function getTemplateObject() {
    return {
      type: $typeSelect.value,
      wentOver: $wentOverInput.val(),
      activities: activities.map((activity) => {
        const val = {
          type: activity.type,
          name: activity.name,
          totalMarks: activity.totalMarks,
        };
        if (activity.type === 1) val.questions = activity.questions.array();
        else if (activity.type === 2) {
          val.items = activity.items.array();
          val.itemMarkingScheme = activity.itemMarkingScheme;
        } else if (activity.type === 3) {
          val.markingScheme = activity.markingScheme;
          val.bonus = activity.bonus;
        }
        return val;
      }),
    };
  }

  function openTraining(data) {
    const { type, date, wentOver, notes } = data,
      attendeesIDs = [];
    if (type) $typeSelect.setOption(type);
    if (wentOver) $wentOverInput.val(wentOver);
    if (notes) $notesInput.val(notes);
    if (date) $dateInput.val(date);
    if (data.attendees) {
      attendees.forEach((attendee) => attendee.deleteAttendee());
      data.attendees.forEach((newAttendee) =>
        attendeesIDs.push(addAttendee(newAttendee).id)
      );
    }
    if (data.activities) {
      data.activities.forEach((activity) => {
        const initSettings = {
          type: activity.type,
          name: activity.name,
          totalMarks: activity.totalMarks,
        };
        if (activity.type === 1) {
          const questionsIDs = AIArray(activity.questions.length);
          initSettings.questions = new Collection(
            activity.questions.map((question, i) => [questionsIDs[i], question])
          );
          if (activity.attendees)
            initSettings.attendees = new Collection(
              activity.attendees.map((attendee, i) => [
                attendeesIDs[i],
                new Collection(
                  attendee.map((question, i) => [questionsIDs[i], question])
                ),
              ])
            );
          guidelinesQuestions(initSettings, true);
        } else if (activity.type === 2) {
          initSettings.itemMarkingScheme = activity.itemMarkingScheme;
          const itemsIDs = AIArray(activity.items.length);
          initSettings.items = new Collection(
            activity.items.map((item, i) => [itemsIDs[i], item])
          );
          if (activity.attendees)
            initSettings.attendees = new Collection(
              activity.attendees.map((attendee, i) => [
                attendeesIDs[i],
                new Collection(attendee.map((item, i) => [itemsIDs[i], item])),
              ])
            );
          multiActivity(initSettings, true);
        } else if (activity.type === 3) {
          initSettings.markingScheme = activity.markingScheme;
          initSettings.bonus = activity.bonus;
          if (activity.attendees)
            initSettings.attendees = new Collection(
              activity.attendees.map((attendee, i) => [
                attendeesIDs[i],
                attendee,
              ])
            );
          simpleActivity(initSettings, true);
        }
      });
    }
  }

  function resetTraining() {
    AUTO_INCREMENT = 0;
    activities.forEach((activity) => activity.deleteActivity());
    attendees.forEach((attendee) => attendee.deleteAttendee());
    coHosts.forEach((coHost) => coHost.deleteCoHost());
    spectators.forEach(spectator => spectator.deleteSpectator());
    addAttendee();
    $typeSelect.setOption(null);
    $(".date input").val(moment().format(config.dateFormat));
    $(".notes textarea").val("");
    $(".wentOver textarea").val("");
    updateAttendeeCounter();
    getGroupAC();
  }

  const $VCCheckerButton = $(
    `<button class="lookFilled colorWhite" tabindex="-1"><i class="fas fa-play"></i></button>`
  )
    .click(() => {
      if (client.connected) {
        client.destroy();
        clearInterval(VCCheckerInt);
        VCCheckerInt = null;
        attendees.forEach((attendee) =>
          attendee.find(".vc").removeClass("vcIn vcOut")
        );
      } else {
        client
          .login({
            clientId: "705448229705220125",
            clientSecret: "fvNvahURtvvAqa_gH0-nWpkLakgUa3Jc",
            scopes: ["rpc"],
          })
          .then(() => {
            client.getSelectedVoiceChannel().then((channel) => {
              if (channel && trainingVCs.includes(channel.id) && !VCCheckerInt)
                VCCheckerInt = setInterval(updateVoiceStatuses, 1000);
            });
            client.subscribe("VOICE_CHANNEL_SELECT", undefined, (data) => {
              if (trainingVCs.includes(data.channel_id)) {
                if (!VCCheckerInt)
                  VCCheckerInt = setInterval(updateVoiceStatuses, 1000);
              } else {
                clearInterval(VCCheckerInt);
                VCCheckerInt = null;
                attendees.forEach((attendee) =>
                  attendee.find(".vc").removeClass("vcIn vcOut")
                );
              }
            });
          })
          .catch(() => client.destroy());
      }
    })
    .appendTo(".vcCheckerThead");

  client.on("disconnected", () =>
    $VCCheckerButton.html(`<i class="fas fa-play"></i>`)
  );
  client.on("connected", () =>
    $VCCheckerButton.html(`<i class="fas fa-stop"></i>`)
  );

  Sortable.create($(".attendees tbody")[0], {
    handle: ".attendeeDragHandle",
    animation: 150,
    onUpdate: updateAttendeeIndexes,
  });

  $(".attendees tfoot td")
    .eq(1)
    .prepend(
      $(
        `<button class="lookFilled colorGreen addAttendee" tabindex="-1"><i class="fas fa-user-plus"></i></button>`
      ).click(() => addAttendee().focus())
    );

  $(".resultThead").append(
    $(
      `<button class="lookFilled colorWhite" tabindex="-1"><i class="fas fa-sync-alt"></i></button>`
    ).click(() => {
      attendees.forEach((attendee) => {
        if ($typeSelect.value === 2 || $typeSelect.value === 4) {
          if (attendee.result === 0) attendee.$resultInput.setOption(1);
        } else {
          if (![0, 1, 2].includes(attendee.result)) return;
          const passed = attendee.hasPassed();
          if (passed === false) attendee.$resultInput.setOption(2);
          else if (passed === null) attendee.$resultInput.setOption(0);
          else if (passed === true) attendee.$resultInput.setOption(1);
        }
      });
    })
  );


  $(".actionButtons").append(
    $(
      `<button class="lookFilled colorBlue widthFitContent openFile" tabindex="-1"><i class="fas fa-folder-open marginRight4"></i> Open file</button>`
    ).click(() => {
      openModal({
        backdropDissmissable: true,
        title: "Open file",
        $footerContent: modalCancel().add(
          $(
            `<button class="lookFilled colorBlue" tabindex="-1">Open</button>`
          ).click(() => {
            ipcRenderer.send("open");
            closeModal();
          })
        ),
      });
      $(".modalContentBody").html(
        `Opening a file or template will <b>reset the current training</b>. Are you sure?`
      );
    })
  );

  $(".actionButtons").append(
    $(
      `<button class="lookFilled colorWhite widthFitContent recordLogButton" tabindex="-1"><i class="fas fa-th-list marginRight4"></i> Generate record</button>`
    ).click(() => {
      openModal({
        backdropDissmissable: true,
        title: "Record log",
        modalClass: "sizeLarge",
        bodyClass: "flex",
        $footerContent: $(
          `<button class="lookFilled colorGreen marginRight8" tabindex="-1"><i class="fas fa-copy marginRight4"></i> Copy</button>`
        )
          .click(() => {
            clipboard.writeText(recordLog());
            makeSwalToast({
              icon: "success",
              title: "Copied to clipboard!",
            });
          })
          .add(
            $(
              `<button class="lookFilled colorWhite" tabindex="-1">Close</button>`
            ).click(closeModal)
          ),
      });
      $(".modalContentBody").append(
        $(`<textarea class="recordLog" readonly>`).val(recordLog())
      );
    })
  );

  $(".actionButtons").append(
    $(
      `<button class="lookFilled colorGreen widthFitContent saveTraining" tabindex="-1"><i class="fas fa-save marginRight4"></i> Save as training</button>`
    ).click(() => {
      ipcRenderer.send(
        "save",
        "training",
        serializeFileName(
          `${$typeSelect.value
            ? trainingTypes.get($typeSelect.value)
            : "training"
          } ${$dateInput.val()}`
        ),
        JSON.stringify(getTrainingObject(), null, "\t")
      );
    })
  );

  $(".actionButtons").append(
    $(
      `<button class="lookFilled colorWhite widthFitContent saveTemplate" tabindex="-1"><i class="fas fa-file-alt marginRight4"></i> Save as template</button>`
    ).click(() => {
      ipcRenderer.send(
        "save",
        "template",
        serializeFileName(
          `${$typeSelect.value
            ? trainingTypes.get($typeSelect.value)
            : "training"
          } template`
        ),
        JSON.stringify(getTemplateObject(), null, "\t")
      );
    })
  );

  $(".actionButtons").append(
    $(
      `<button class="lookFilled colorRed widthFitContent" tabindex="-1"><i class="fas fa-trash-alt marginRight4"></i> Reset</button>`
    ).click(() => {
      openModal({
        backdropDissmissable: true,
        title: "Reset training",
        $footerContent: modalCancel().add(
          $(
            `<button class="lookFilled colorRed" tabindex="-1">Reset</button>`
          ).click(() => {
            resetTraining();
            closeModal();
            makeSwalToast({
              icon: "success",
              title: `Training successfully resetted!`,
            });
          })
        ),
      });
      $(".modalContentBody").html(
        `Are you sure you want to <b>reset the training</b>?`
      );
    })
  );

  $(".actionButtons").append(
    $(
      `<button class="lookFilled colorWhite widthFitContent customize" tabindex="-1"><i class="fas fa-paint-brush"></i> Customize</button>`
    ).click(() => {
      openModal({
        title: "Customization",
        modalClass: "sizeMedium",
        bodyClass: "flex directionColumn",
        $footerContent: $(
          `<button class="lookFilled colorRed marginRightAuto" tabindex="-1">Reset defaults</button>`
        )
          .click(() => {
            $topLevel.val(DEFAULT_CONFIG.recordLog.topLevel);
            $rankSubset.val(DEFAULT_CONFIG.recordLog.rankSubset);
            $attendeeRow.val(DEFAULT_CONFIG.recordLog.attendeeRow);
            $attendeeScores.val(DEFAULT_CONFIG.recordLog.attendeeScores);
            $activityScore.val(DEFAULT_CONFIG.recordLog.activityScore);
            $totalScore.val(DEFAULT_CONFIG.recordLog.totalScore);
            $totalPercentage.val(DEFAULT_CONFIG.recordLog.totalPercentage);
            $activityScoresSep.val(DEFAULT_CONFIG.recordLog.activityScoresSep);
            $attendeeOutcome.val(DEFAULT_CONFIG.recordLog.attendeeOutcome);
            $passed.val(DEFAULT_CONFIG.recordLog.passed);
            $failed.val(DEFAULT_CONFIG.recordLog.failed);
            $dismissed.val(DEFAULT_CONFIG.recordLog.dismissed);
            $leftNoDismissal.val(DEFAULT_CONFIG.recordLog.leftNoDismissal);
            $award.val(DEFAULT_CONFIG.recordLog.award);
            $attendeeNotes.val(DEFAULT_CONFIG.recordLog.attendeeNotes);
            $wentOver.val(DEFAULT_CONFIG.recordLog.wentOver);
            $NAValue.val(DEFAULT_CONFIG.recordLog.NAValue);

            dateFormat
              .get(
                dateFormats.findKey(
                  (format) => format === DEFAULT_CONFIG.dateFormat
                )
              )
              .select();
          })
          .add(modalCancel())
          .add(
            $(
              `<button class="lookFilled colorWhite" tabindex="-1">Save</button>`
            ).click(submit)
          ),
      });
      const $topLevel = $(
        `<textarea rows="10" class="flexNoShrink marginBottomSmall">`
      ).val(config.recordLog.topLevel);
      const $rankSubset = $(
        `<textarea rows="3" class="flexNoShrink marginBottomSmall">`
      ).val(config.recordLog.rankSubset);
      const $attendeeRow = $(
        `<textarea rows="1" class="flexNoShrink marginBottomSmall">`
      ).val(config.recordLog.attendeeRow);
      const $attendeeScores = $(
        `<textarea rows="1" class="flexNoShrink marginBottomSmall">`
      ).val(config.recordLog.attendeeScores);
      const $activityScore = $(
        `<textarea rows="1" class="flexNoShrink marginBottomSmall">`
      ).val(config.recordLog.activityScore);
      const $totalScore = $(
        `<textarea rows="1" class="flexNoShrink marginBottomSmall">`
      ).val(config.recordLog.totalScore);
      const $totalPercentage = $(
        `<textarea rows="1" class="flexNoShrink marginBottomSmall">`
      ).val(config.recordLog.totalPercentage);
      const $activityScoresSep = $(
        `<textarea rows="1" class="flexNoShrink marginBottomSmall">`
      ).val(config.recordLog.activityScoresSep);
      const $attendeeOutcome = $(
        `<textarea rows="1" class="flexNoShrink marginBottomSmall">`
      ).val(config.recordLog.attendeeOutcome);
      const $passed = $(`<textarea rows="1" class="marginLeft8">`).val(
        config.recordLog.passed
      );
      const $failed = $(`<textarea rows="1" class="marginLeft8">`).val(
        config.recordLog.failed
      );
      const $dismissed = $(`<textarea rows="1" class="marginLeft8">`).val(
        config.recordLog.dismissed
      );
      const $leftNoDismissal = $(`<textarea rows="1" class="marginLeft8">`).val(
        config.recordLog.leftNoDismissal
      );
      const $award = $(
        `<textarea rows="1" class="flexNoShrink marginBottomSmall">`
      ).val(config.recordLog.award);
      const $attendeeNotes = $(
        `<textarea rows="1" class="flexNoShrink marginBottomSmall">`
      ).val(config.recordLog.attendeeNotes);
      const $wentOver = $(
        `<textarea rows="1" class="flexNoShrink marginBottomSmall">`
      ).val(config.recordLog.wentOver);
      const $NAValue = $(
        `<textarea rows="1" class="flexNoShrink marginBottomSmall">`
      ).val(config.recordLog.NAValue);

      const dateFormat = checkboxGroup(dateFormats, "marginRight8");
      dateFormat
        .get(dateFormats.findKey((format) => format === config.dateFormat))
        .select();

      $(".modalContentBody")
        .append(`<h4 class="modalH4 white textCenter size16 height20 weightSemiBold marginBottom8">Record log</h4>
		<p class="marginBottom8"><span class="white weightSemiBold">Top-level format:</span> this represents the top-level part of the record. Use the text area below to modify the record format. The following variables may be included: <span class="variable">{{type}}</span>, <span class="variable">{{coHosts}}</span>, <span class="variable">{{spectators}}</span>, <span class="variable">{{wentOver}}</span>, <span class="variable">{{date}}</span>, <span class="variable">{{notes}}</span> and <span class="variable">{{attendees}}</span>.</p>`);
      $(".modalContentBody").append($topLevel);
      $(".modalContentBody").append(
        `<p class="marginBottom8"><span class="white weightSemiBold">Attendees rank subsets:</span> this represents the format of an entire rank subset. The following variables may be included: <span class="variable">{{rank}}</span> and <span class="variable">{{attendees}}</span>.</p>`
      );
      $(".modalContentBody").append($rankSubset);
      $(".modalContentBody").append(
        `<p class="marginBottom8"><span class="white weightSemiBold">Attendee rows:</span> this represents the format of an attendee's outcome row. The following variables may be included: <span class="variable">{{username}}</span>, <span class="variable">{{scores}}</span>, <span class="variable">{{outcome}}</span>, <span class="variable">{{award}}</span> and <span class="variable">{{notes}}</span>.</p>`
      );
      $(".modalContentBody").append($attendeeRow);
      $(".modalContentBody").append(
        `<p class="marginBottom8"><span class="white weightSemiBold">Attendee scores:</span> this represents the format of an attendee's scores in his outcome row. The following variables may be included: <span class="variable">{{activitiesScores}}</span>, <span class="variable">{{totalScore}}</span> and <span class="variable">{{totalPercentage}}</span>.</p>`
      );
      $(".modalContentBody").append($attendeeScores);
      $(".modalContentBody").append(
        `<p class="marginBottom8"><span class="white weightSemiBold">Activity score:</span> this represents the score of an activity in an attendee's outcome row. The following variables may be included: <span class="variable">{{activityName}}</span>, <span class="variable">{{score}}</span>, <span class="variable">{{maxScore}}</span>.</p>`
      );
      $(".modalContentBody").append($activityScore);
      $(".modalContentBody").append(
        `<p class="marginBottom8"><span class="white weightSemiBold">Total score:</span> this represents the total score of an attendee in his outcome row. The following variables may be included: <span class="variable">{{score}}</span> and <span class="variable">{{maxScore}}</span>.</p>`
      );
      $(".modalContentBody").append($totalScore);
      $(".modalContentBody").append(
        `<p class="marginBottom8"><span class="white weightSemiBold">Total percentage:</span> this represents the total score percentage of an attendee in his outcome row. The following variables may be included: <span class="variable">{{percentage}}</span>.</p>`
      );
      $(".modalContentBody").append($totalPercentage);
      $(".modalContentBody").append(
        `<p class="marginBottom8"><span class="white weightSemiBold">Activities scores separator:</span> this represents what separates activities scores in an attendee's outcome row.</p>`
      );
      $(".modalContentBody").append($activityScoresSep);
      $(".modalContentBody").append(
        `<p class="marginBottom8"><span class="white weightSemiBold">Attendee outcome:</span> this represents the outcome of an attendee in his outcome row. The following variables may be included: <span class="variable">{{outcome}}</span> (will be uppercased).</p>`
      );
      $(".modalContentBody").append($attendeeOutcome);
      $(".modalContentBody").append(
        `<p class="marginBottom8 white weightSemiBold">Outcomes:</p>`
      );
      $(".modalContentBody").append(
        $(`<div class="flex alignCenter marginBottom4">
			<button class="ghostButton attendeeResult passed" tabindex="-1"><i class="fas fa-check-square"></i></button>
		</div>`).append($passed)
      );
      $(".modalContentBody").append(
        $(`<div class="flex alignCenter marginBottom4">
			<button class="ghostButton attendeeResult failed" tabindex="-1"><i class="fas fa-ban"></i></button>
		</div>`).append($failed)
      );
      $(".modalContentBody").append(
        $(`<div class="flex alignCenter marginBottom4">
			<button class="ghostButton attendeeResult dismissed" tabindex="-1"><i class="fas fa-user-clock"></i></button>
		</div>`).append($dismissed)
      );
      $(".modalContentBody").append(
        $(`<div class="flex alignCenter marginBottom4">
			<button class="ghostButton attendeeResult leftNoDismissal" tabindex="-1"><i class="fas fa-user-times"></i></button>
		</div>`).append($leftNoDismissal)
      );
      $(".modalContentBody").append(
        `<p class="marginBottom8"><span class="white weightSemiBold">Award:</span> this represents the awards label in an attendee's outcome row if applicable. It will be uppercased.</p>`
      );
      $(".modalContentBody").append($award);
      $(".modalContentBody").append(
        `<p class="marginBottom8"><span class="white weightSemiBold">Attendee notes:</span> this represents notes about an attendee in his outcome row if applicable. The following variables may be included: <span class="variable">{{notes}}</span>.</p>`
      );
      $(".modalContentBody").append($attendeeNotes);
      $(".modalContentBody").append(
        `<p class="marginBottom8"><span class="white weightSemiBold">Went over:</span> this represents every row of the went over. The following variables may be included: <span class="variable">{{row}}</span>.</p>`
      );
      $(".modalContentBody").append($wentOver);
      $(".modalContentBody").append(
        `<p class="marginBottom8"><span class="white weightSemiBold">N/A value:</span> this is a placeholder for not-applicable values.</p>`
      );
      $(".modalContentBody").append($NAValue);

      $(".modalContentBody").append(
        `<h4 class="modalH4 white textCenter size16 height20 weightSemiBold marginBottom8">Date format</h4>`
      );
      $(".modalContentBody").append(
        $(
          `<div class="flex alignCenter marginBottom8"> MM/DD/YYYY</div>`
        ).prepend(dateFormat.get(1))
      );
      $(".modalContentBody").append(
        $(
          `<div class="flex alignCenter marginBottom8"> DD/MM/YYYY</div>`
        ).prepend(dateFormat.get(2))
      );
      $(".modalContentBody").append(
        `<h4 class="modalH4 white textCenter size16 height20 weightSemiBold marginBottom8">Background Colour</h4>`
      );
      $(".modalContentBody").append(
        $(`<button class="lookFilled colorGrey" tabindex="-1">Dark Mode</button>`)
          .click(() => {
            $(".contentWrapper").css({
              background: `#202225`,
              color: `white`,
            })

            $(".attendees").css({
              background: `#2b2d32`,
            });
      
            $(".attendees th").css({
              background: `#272a2d`,
            });

            $("textarea").css({
              background: `#2b2d32`,
            });

            $(".input").css({
              background: `#464a52`,
            });

            $(".select button").css({
              background: `#464a52`,
            });

            $(".selectDropdown").css({
              background: `#464a52`,
            });

            $(".marginLeftSmall").css({
              background: `#464a52`,
            });
          })
      );
      $(".modalContentBody").append(
        $(`<button class="lookFilled colorGreyGradient" tabindex="-1">Dark Mode (Gradient)</button>`)
          .click(() => {
            $(".contentWrapper").css({
              background: `linear-gradient(to bottom right, #202225, #1a1d1f, #2c2f33)`,
              color: `white`,
            })
            
            $(".attendees").css({
              background: `#2b2d32`,
            });
      
            $(".attendees th").css({
              background: `#272a2d`,
            });

            $("textarea").css({
              background: `#2b2d32`,
            });

            $(".input").css({
              background: `#464a52`,
            });

            $(".select button").css({
              background: `#464a52`,
            });

            $(".selectDropdown").css({
              background: `#464a52`,
            });

            $(".marginLeftSmall").css({
              background: `#464a52`,
            });
          })
      );
      $(".modalContentBody").append(
        $(`<button class="lookFilled colorAurora" tabindex="-1">Aurora Gradient</button>`)
          .click(() => {
            $(".contentWrapper").css({
              background: `linear-gradient(to bottom right, #070e44, #04280f, #070e44)`,
              color: `white`,
            });
      
            $(".attendees").css({
              background: `#0000003b`,
            });
      
            $(".attendees th").css({
              background: `#0000003b`,
            });

            $("textarea").css({
              background: `#0000003b`,
            });

            $(".input").css({
              background: `#0000003b`,
            });

            $(".select button").css({
              background: `#0000003b`,
            });

            $(".selectDropdown").css({
              background: `#0000003b`,
            });

            $(".marginLeftSmall").css({
              background: `#0000003b`,
            });
          })
      );
      $(".modalContentBody").append(
        $(`<button class="lookFilled colorBlurple" tabindex="-1">Midnight Purple</button>`)
          .click(() => {
            $(".contentWrapper").css({
              background: `linear-gradient(to bottom right, #0b094f, #010112)`,
              color: `white`,
            });
      
            $(".attendees").css({
              background: `#0000003b`,
            });
      
            $(".attendees th").css({
              background: `#0000003b`,
            });

            $("textarea").css({
              background: `#0000003b`,
            });

            $(".input").css({
              background: `#0000003b`,
            });

            $(".select button").css({
              background: `#0000003b`,
            });

            $(".selectDropdown").css({
              background: `#0000003b`,
            });

            $(".marginLeftSmall").css({
              background: `#0000003b`,
            });
          })
      );
      //#2b2d32 #0000003b .marginLeftSmall
      

      function submit() {
        config = {
          recordLog: {
            topLevel: $topLevel.val(),
            rankSubset: $rankSubset.val(),
            attendeeRow: $attendeeRow.val(),
            attendeeScores: $attendeeScores.val(),
            activityScore: $activityScore.val(),
            totalScore: $totalScore.val(),
            totalPercentage: $totalPercentage.val(),
            activityScoresSep: $activityScoresSep.val(),
            attendeeOutcome: $attendeeOutcome.val(),
            passed: $passed.val(),
            failed: $failed.val(),
            dismissed: $dismissed.val(),
            leftNoDismissal: $leftNoDismissal.val(),
            award: $award.val(),
            attendeeNotes: $attendeeNotes.val(),
            wentOver: $wentOver.val(),
            NAValue: $NAValue.val(),
          },
          dateFormat: dateFormat.value,
        };
        fs.writeFileSync("./config.json", JSON.stringify(config, null, 4));
        closeModal();
      }
    })
  );

  $(".actionButtons").append(
    $(
      `<button class="lookFilled colorWhite widthFitContent" tabindex="-1"><i class="fas fa-question-circle marginRight4"></i> Tutorial</button>`
    ).click(() => playTutorial())
  );

  $(".actionButtons").append(
    `<span class="marginLeftSmall">SD Training Utility</span>`
  );

  $(".actionButtons").append(
    `<span class="marginLeftSmall"><b>Version 1.10.3</b></span>`
  );

  ipcRenderer.on("saveSuccess", (e, type) => {
    makeSwalToast({
      icon: "success",
      title: `${type === "training" ? "Training" : "Template"
        } successfully saved!`,
    });
  });

  ipcRenderer.on("openFail", () => {
    makeSwalToast({
      icon: "error",
      title: "Coudldn't parse the file properly.",
    });
  });

  ipcRenderer.on("openSuccess", (e, data) => {
    resetTraining();
    try {
      openTraining(data);
      makeSwalToast({
        icon: "success",
        title: "File successfully loaded!",
      });
    } catch {
      resetTraining();
      makeSwalToast({
        icon: "error",
        title: "Failed to parse the training file.",
      });
    }
  });

  resetTraining();

  setInterval(() => {
    ipcRenderer.send("autosave", JSON.stringify(getTrainingObject()));
  }, 3e4);
});
