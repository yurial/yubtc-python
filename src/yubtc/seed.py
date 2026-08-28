# flake8: noqa: E501
# The BIP-39 wordlist has long words (up to 8 chars) packed densely per line;
# splitting them differently would just shuffle E501 hits around without
# improving readability. Suppress E501 for the whole file.
from collections.abc import Callable, Iterable

from yubtc.util import NotNone, require_kwargs_only

# The BIP-39 English wordlist: 2048 words in the exact BIP-39 order. The
# order IS consensus data -- a word's index supplies 11 bits of the
# mnemonic entropy -- so any re-ordering silently breaks every existing
# seed. Pinned by `test_generate_seed_uses_bip39_wordlist` and by the
# parse/checksum tests below.
BIP39_WORDLIST = (
    'abandon', 'ability', 'able', 'about', 'above', 'absent', 'absorb', 'abstract', 'absurd', 'abuse',
    'access', 'accident', 'account', 'accuse', 'achieve', 'acid', 'acoustic', 'acquire', 'across', 'act',
    'action', 'actor', 'actress', 'actual', 'adapt', 'add', 'addict', 'address', 'adjust', 'admit', 'adult',
    'advance', 'advice', 'aerobic', 'affair', 'afford', 'afraid', 'again', 'age', 'agent', 'agree', 'ahead',
    'aim', 'air', 'airport', 'aisle', 'alarm', 'album', 'alcohol', 'alert', 'alien', 'all', 'alley', 'allow',
    'almost', 'alone', 'alpha', 'already', 'also', 'alter', 'always', 'amateur', 'amazing', 'among',
    'amount', 'amused', 'analyst', 'anchor', 'ancient', 'anger', 'angle', 'angry', 'animal', 'ankle',
    'announce', 'annual', 'another', 'answer', 'antenna', 'antique', 'anxiety', 'any', 'apart', 'apology',
    'appear', 'apple', 'approve', 'april', 'arch', 'arctic', 'area', 'arena', 'argue', 'arm', 'armed',
    'armor', 'army', 'around', 'arrange', 'arrest', 'arrive', 'arrow', 'art', 'artefact', 'artist',
    'artwork', 'ask', 'aspect', 'assault', 'asset', 'assist', 'assume', 'asthma', 'athlete', 'atom',
    'attack', 'attend', 'attitude', 'attract', 'auction', 'audit', 'august', 'aunt', 'author', 'auto',
    'autumn', 'average', 'avocado', 'avoid', 'awake', 'aware', 'away', 'awesome', 'awful', 'awkward', 'axis',
    'baby', 'bachelor', 'bacon', 'badge', 'bag', 'balance', 'balcony', 'ball', 'bamboo', 'banana', 'banner',
    'bar', 'barely', 'bargain', 'barrel', 'base', 'basic', 'basket', 'battle', 'beach', 'bean', 'beauty',
    'because', 'become', 'beef', 'before', 'begin', 'behave', 'behind', 'believe', 'below', 'belt', 'bench',
    'benefit', 'best', 'betray', 'better', 'between', 'beyond', 'bicycle', 'bid', 'bike', 'bind', 'biology',
    'bird', 'birth', 'bitter', 'black', 'blade', 'blame', 'blanket', 'blast', 'bleak', 'bless', 'blind',
    'blood', 'blossom', 'blouse', 'blue', 'blur', 'blush', 'board', 'boat', 'body', 'boil', 'bomb', 'bone',
    'bonus', 'book', 'boost', 'border', 'boring', 'borrow', 'boss', 'bottom', 'bounce', 'box', 'boy',
    'bracket', 'brain', 'brand', 'brass', 'brave', 'bread', 'breeze', 'brick', 'bridge', 'brief', 'bright',
    'bring', 'brisk', 'broccoli', 'broken', 'bronze', 'broom', 'brother', 'brown', 'brush', 'bubble',
    'buddy', 'budget', 'buffalo', 'build', 'bulb', 'bulk', 'bullet', 'bundle', 'bunker', 'burden', 'burger',
    'burst', 'bus', 'business', 'busy', 'butter', 'buyer', 'buzz', 'cabbage', 'cabin', 'cable', 'cactus',
    'cage', 'cake', 'call', 'calm', 'camera', 'camp', 'can', 'canal', 'cancel', 'candy', 'cannon', 'canoe',
    'canvas', 'canyon', 'capable', 'capital', 'captain', 'car', 'carbon', 'card', 'cargo', 'carpet', 'carry',
    'cart', 'case', 'cash', 'casino', 'castle', 'casual', 'cat', 'catalog', 'catch', 'category', 'cattle',
    'caught', 'cause', 'caution', 'cave', 'ceiling', 'celery', 'cement', 'census', 'century', 'cereal',
    'certain', 'chair', 'chalk', 'champion', 'change', 'chaos', 'chapter', 'charge', 'chase', 'chat',
    'cheap', 'check', 'cheese', 'chef', 'cherry', 'chest', 'chicken', 'chief', 'child', 'chimney', 'choice',
    'choose', 'chronic', 'chuckle', 'chunk', 'churn', 'cigar', 'cinnamon', 'circle', 'citizen', 'city',
    'civil', 'claim', 'clap', 'clarify', 'claw', 'clay', 'clean', 'clerk', 'clever', 'click', 'client',
    'cliff', 'climb', 'clinic', 'clip', 'clock', 'clog', 'close', 'cloth', 'cloud', 'clown', 'club', 'clump',
    'cluster', 'clutch', 'coach', 'coast', 'coconut', 'code', 'coffee', 'coil', 'coin', 'collect', 'color',
    'column', 'combine', 'come', 'comfort', 'comic', 'common', 'company', 'concert', 'conduct', 'confirm',
    'congress', 'connect', 'consider', 'control', 'convince', 'cook', 'cool', 'copper', 'copy', 'coral',
    'core', 'corn', 'correct', 'cost', 'cotton', 'couch', 'country', 'couple', 'course', 'cousin', 'cover',
    'coyote', 'crack', 'cradle', 'craft', 'cram', 'crane', 'crash', 'crater', 'crawl', 'crazy', 'cream',
    'credit', 'creek', 'crew', 'cricket', 'crime', 'crisp', 'critic', 'crop', 'cross', 'crouch', 'crowd',
    'crucial', 'cruel', 'cruise', 'crumble', 'crunch', 'crush', 'cry', 'crystal', 'cube', 'culture', 'cup',
    'cupboard', 'curious', 'current', 'curtain', 'curve', 'cushion', 'custom', 'cute', 'cycle', 'dad',
    'damage', 'damp', 'dance', 'danger', 'daring', 'dash', 'daughter', 'dawn', 'day', 'deal', 'debate',
    'debris', 'decade', 'december', 'decide', 'decline', 'decorate', 'decrease', 'deer', 'defense', 'define',
    'defy', 'degree', 'delay', 'deliver', 'demand', 'demise', 'denial', 'dentist', 'deny', 'depart',
    'depend', 'deposit', 'depth', 'deputy', 'derive', 'describe', 'desert', 'design', 'desk', 'despair',
    'destroy', 'detail', 'detect', 'develop', 'device', 'devote', 'diagram', 'dial', 'diamond', 'diary',
    'dice', 'diesel', 'diet', 'differ', 'digital', 'dignity', 'dilemma', 'dinner', 'dinosaur', 'direct',
    'dirt', 'disagree', 'discover', 'disease', 'dish', 'dismiss', 'disorder', 'display', 'distance',
    'divert', 'divide', 'divorce', 'dizzy', 'doctor', 'document', 'dog', 'doll', 'dolphin', 'domain',
    'donate', 'donkey', 'donor', 'door', 'dose', 'double', 'dove', 'draft', 'dragon', 'drama', 'drastic',
    'draw', 'dream', 'dress', 'drift', 'drill', 'drink', 'drip', 'drive', 'drop', 'drum', 'dry', 'duck',
    'dumb', 'dune', 'during', 'dust', 'dutch', 'duty', 'dwarf', 'dynamic', 'eager', 'eagle', 'early', 'earn',
    'earth', 'easily', 'east', 'easy', 'echo', 'ecology', 'economy', 'edge', 'edit', 'educate', 'effort',
    'egg', 'eight', 'either', 'elbow', 'elder', 'electric', 'elegant', 'element', 'elephant', 'elevator',
    'elite', 'else', 'embark', 'embody', 'embrace', 'emerge', 'emotion', 'employ', 'empower', 'empty',
    'enable', 'enact', 'end', 'endless', 'endorse', 'enemy', 'energy', 'enforce', 'engage', 'engine',
    'enhance', 'enjoy', 'enlist', 'enough', 'enrich', 'enroll', 'ensure', 'enter', 'entire', 'entry',
    'envelope', 'episode', 'equal', 'equip', 'era', 'erase', 'erode', 'erosion', 'error', 'erupt', 'escape',
    'essay', 'essence', 'estate', 'eternal', 'ethics', 'evidence', 'evil', 'evoke', 'evolve', 'exact',
    'example', 'excess', 'exchange', 'excite', 'exclude', 'excuse', 'execute', 'exercise', 'exhaust',
    'exhibit', 'exile', 'exist', 'exit', 'exotic', 'expand', 'expect', 'expire', 'explain', 'expose',
    'express', 'extend', 'extra', 'eye', 'eyebrow', 'fabric', 'face', 'faculty', 'fade', 'faint', 'faith',
    'fall', 'false', 'fame', 'family', 'famous', 'fan', 'fancy', 'fantasy', 'farm', 'fashion', 'fat',
    'fatal', 'father', 'fatigue', 'fault', 'favorite', 'feature', 'february', 'federal', 'fee', 'feed',
    'feel', 'female', 'fence', 'festival', 'fetch', 'fever', 'few', 'fiber', 'fiction', 'field', 'figure',
    'file', 'film', 'filter', 'final', 'find', 'fine', 'finger', 'finish', 'fire', 'firm', 'first', 'fiscal',
    'fish', 'fit', 'fitness', 'fix', 'flag', 'flame', 'flash', 'flat', 'flavor', 'flee', 'flight', 'flip',
    'float', 'flock', 'floor', 'flower', 'fluid', 'flush', 'fly', 'foam', 'focus', 'fog', 'foil', 'fold',
    'follow', 'food', 'foot', 'force', 'forest', 'forget', 'fork', 'fortune', 'forum', 'forward', 'fossil',
    'foster', 'found', 'fox', 'fragile', 'frame', 'frequent', 'fresh', 'friend', 'fringe', 'frog', 'front',
    'frost', 'frown', 'frozen', 'fruit', 'fuel', 'fun', 'funny', 'furnace', 'fury', 'future', 'gadget',
    'gain', 'galaxy', 'gallery', 'game', 'gap', 'garage', 'garbage', 'garden', 'garlic', 'garment', 'gas',
    'gasp', 'gate', 'gather', 'gauge', 'gaze', 'general', 'genius', 'genre', 'gentle', 'genuine', 'gesture',
    'ghost', 'giant', 'gift', 'giggle', 'ginger', 'giraffe', 'girl', 'give', 'glad', 'glance', 'glare',
    'glass', 'glide', 'glimpse', 'globe', 'gloom', 'glory', 'glove', 'glow', 'glue', 'goat', 'goddess',
    'gold', 'good', 'goose', 'gorilla', 'gospel', 'gossip', 'govern', 'gown', 'grab', 'grace', 'grain',
    'grant', 'grape', 'grass', 'gravity', 'great', 'green', 'grid', 'grief', 'grit', 'grocery', 'group',
    'grow', 'grunt', 'guard', 'guess', 'guide', 'guilt', 'guitar', 'gun', 'gym', 'habit', 'hair', 'half',
    'hammer', 'hamster', 'hand', 'happy', 'harbor', 'hard', 'harsh', 'harvest', 'hat', 'have', 'hawk',
    'hazard', 'head', 'health', 'heart', 'heavy', 'hedgehog', 'height', 'hello', 'helmet', 'help', 'hen',
    'hero', 'hidden', 'high', 'hill', 'hint', 'hip', 'hire', 'history', 'hobby', 'hockey', 'hold', 'hole',
    'holiday', 'hollow', 'home', 'honey', 'hood', 'hope', 'horn', 'horror', 'horse', 'hospital', 'host',
    'hotel', 'hour', 'hover', 'hub', 'huge', 'human', 'humble', 'humor', 'hundred', 'hungry', 'hunt',
    'hurdle', 'hurry', 'hurt', 'husband', 'hybrid', 'ice', 'icon', 'idea', 'identify', 'idle', 'ignore',
    'ill', 'illegal', 'illness', 'image', 'imitate', 'immense', 'immune', 'impact', 'impose', 'improve',
    'impulse', 'inch', 'include', 'income', 'increase', 'index', 'indicate', 'indoor', 'industry', 'infant',
    'inflict', 'inform', 'inhale', 'inherit', 'initial', 'inject', 'injury', 'inmate', 'inner', 'innocent',
    'input', 'inquiry', 'insane', 'insect', 'inside', 'inspire', 'install', 'intact', 'interest', 'into',
    'invest', 'invite', 'involve', 'iron', 'island', 'isolate', 'issue', 'item', 'ivory', 'jacket', 'jaguar',
    'jar', 'jazz', 'jealous', 'jeans', 'jelly', 'jewel', 'job', 'join', 'joke', 'journey', 'joy', 'judge',
    'juice', 'jump', 'jungle', 'junior', 'junk', 'just', 'kangaroo', 'keen', 'keep', 'ketchup', 'key',
    'kick', 'kid', 'kidney', 'kind', 'kingdom', 'kiss', 'kit', 'kitchen', 'kite', 'kitten', 'kiwi', 'knee',
    'knife', 'knock', 'know', 'lab', 'label', 'labor', 'ladder', 'lady', 'lake', 'lamp', 'language',
    'laptop', 'large', 'later', 'latin', 'laugh', 'laundry', 'lava', 'law', 'lawn', 'lawsuit', 'layer',
    'lazy', 'leader', 'leaf', 'learn', 'leave', 'lecture', 'left', 'leg', 'legal', 'legend', 'leisure',
    'lemon', 'lend', 'length', 'lens', 'leopard', 'lesson', 'letter', 'level', 'liar', 'liberty', 'library',
    'license', 'life', 'lift', 'light', 'like', 'limb', 'limit', 'link', 'lion', 'liquid', 'list', 'little',
    'live', 'lizard', 'load', 'loan', 'lobster', 'local', 'lock', 'logic', 'lonely', 'long', 'loop',
    'lottery', 'loud', 'lounge', 'love', 'loyal', 'lucky', 'luggage', 'lumber', 'lunar', 'lunch', 'luxury',
    'lyrics', 'machine', 'mad', 'magic', 'magnet', 'maid', 'mail', 'main', 'major', 'make', 'mammal', 'man',
    'manage', 'mandate', 'mango', 'mansion', 'manual', 'maple', 'marble', 'march', 'margin', 'marine',
    'market', 'marriage', 'mask', 'mass', 'master', 'match', 'material', 'math', 'matrix', 'matter',
    'maximum', 'maze', 'meadow', 'mean', 'measure', 'meat', 'mechanic', 'medal', 'media', 'melody', 'melt',
    'member', 'memory', 'mention', 'menu', 'mercy', 'merge', 'merit', 'merry', 'mesh', 'message', 'metal',
    'method', 'middle', 'midnight', 'milk', 'million', 'mimic', 'mind', 'minimum', 'minor', 'minute',
    'miracle', 'mirror', 'misery', 'miss', 'mistake', 'mix', 'mixed', 'mixture', 'mobile', 'model', 'modify',
    'mom', 'moment', 'monitor', 'monkey', 'monster', 'month', 'moon', 'moral', 'more', 'morning', 'mosquito',
    'mother', 'motion', 'motor', 'mountain', 'mouse', 'move', 'movie', 'much', 'muffin', 'mule', 'multiply',
    'muscle', 'museum', 'mushroom', 'music', 'must', 'mutual', 'myself', 'mystery', 'myth', 'naive', 'name',
    'napkin', 'narrow', 'nasty', 'nation', 'nature', 'near', 'neck', 'need', 'negative', 'neglect',
    'neither', 'nephew', 'nerve', 'nest', 'net', 'network', 'neutral', 'never', 'news', 'next', 'nice',
    'night', 'noble', 'noise', 'nominee', 'noodle', 'normal', 'north', 'nose', 'notable', 'note', 'nothing',
    'notice', 'novel', 'now', 'nuclear', 'number', 'nurse', 'nut', 'oak', 'obey', 'object', 'oblige',
    'obscure', 'observe', 'obtain', 'obvious', 'occur', 'ocean', 'october', 'odor', 'off', 'offer', 'office',
    'often', 'oil', 'okay', 'old', 'olive', 'olympic', 'omit', 'once', 'one', 'onion', 'online', 'only',
    'open', 'opera', 'opinion', 'oppose', 'option', 'orange', 'orbit', 'orchard', 'order', 'ordinary',
    'organ', 'orient', 'original', 'orphan', 'ostrich', 'other', 'outdoor', 'outer', 'output', 'outside',
    'oval', 'oven', 'over', 'own', 'owner', 'oxygen', 'oyster', 'ozone', 'pact', 'paddle', 'page', 'pair',
    'palace', 'palm', 'panda', 'panel', 'panic', 'panther', 'paper', 'parade', 'parent', 'park', 'parrot',
    'party', 'pass', 'patch', 'path', 'patient', 'patrol', 'pattern', 'pause', 'pave', 'payment', 'peace',
    'peanut', 'pear', 'peasant', 'pelican', 'pen', 'penalty', 'pencil', 'people', 'pepper', 'perfect',
    'permit', 'person', 'pet', 'phone', 'photo', 'phrase', 'physical', 'piano', 'picnic', 'picture', 'piece',
    'pig', 'pigeon', 'pill', 'pilot', 'pink', 'pioneer', 'pipe', 'pistol', 'pitch', 'pizza', 'place',
    'planet', 'plastic', 'plate', 'play', 'please', 'pledge', 'pluck', 'plug', 'plunge', 'poem', 'poet',
    'point', 'polar', 'pole', 'police', 'pond', 'pony', 'pool', 'popular', 'portion', 'position', 'possible',
    'post', 'potato', 'pottery', 'poverty', 'powder', 'power', 'practice', 'praise', 'predict', 'prefer',
    'prepare', 'present', 'pretty', 'prevent', 'price', 'pride', 'primary', 'print', 'priority', 'prison',
    'private', 'prize', 'problem', 'process', 'produce', 'profit', 'program', 'project', 'promote', 'proof',
    'property', 'prosper', 'protect', 'proud', 'provide', 'public', 'pudding', 'pull', 'pulp', 'pulse',
    'pumpkin', 'punch', 'pupil', 'puppy', 'purchase', 'purity', 'purpose', 'purse', 'push', 'put', 'puzzle',
    'pyramid', 'quality', 'quantum', 'quarter', 'question', 'quick', 'quit', 'quiz', 'quote', 'rabbit',
    'raccoon', 'race', 'rack', 'radar', 'radio', 'rail', 'rain', 'raise', 'rally', 'ramp', 'ranch', 'random',
    'range', 'rapid', 'rare', 'rate', 'rather', 'raven', 'raw', 'razor', 'ready', 'real', 'reason', 'rebel',
    'rebuild', 'recall', 'receive', 'recipe', 'record', 'recycle', 'reduce', 'reflect', 'reform', 'refuse',
    'region', 'regret', 'regular', 'reject', 'relax', 'release', 'relief', 'rely', 'remain', 'remember',
    'remind', 'remove', 'render', 'renew', 'rent', 'reopen', 'repair', 'repeat', 'replace', 'report',
    'require', 'rescue', 'resemble', 'resist', 'resource', 'response', 'result', 'retire', 'retreat',
    'return', 'reunion', 'reveal', 'review', 'reward', 'rhythm', 'rib', 'ribbon', 'rice', 'rich', 'ride',
    'ridge', 'rifle', 'right', 'rigid', 'ring', 'riot', 'ripple', 'risk', 'ritual', 'rival', 'river', 'road',
    'roast', 'robot', 'robust', 'rocket', 'romance', 'roof', 'rookie', 'room', 'rose', 'rotate', 'rough',
    'round', 'route', 'royal', 'rubber', 'rude', 'rug', 'rule', 'run', 'runway', 'rural', 'sad', 'saddle',
    'sadness', 'safe', 'sail', 'salad', 'salmon', 'salon', 'salt', 'salute', 'same', 'sample', 'sand',
    'satisfy', 'satoshi', 'sauce', 'sausage', 'save', 'say', 'scale', 'scan', 'scare', 'scatter', 'scene',
    'scheme', 'school', 'science', 'scissors', 'scorpion', 'scout', 'scrap', 'screen', 'script', 'scrub',
    'sea', 'search', 'season', 'seat', 'second', 'secret', 'section', 'security', 'seed', 'seek', 'segment',
    'select', 'sell', 'seminar', 'senior', 'sense', 'sentence', 'series', 'service', 'session', 'settle',
    'setup', 'seven', 'shadow', 'shaft', 'shallow', 'share', 'shed', 'shell', 'sheriff', 'shield', 'shift',
    'shine', 'ship', 'shiver', 'shock', 'shoe', 'shoot', 'shop', 'short', 'shoulder', 'shove', 'shrimp',
    'shrug', 'shuffle', 'shy', 'sibling', 'sick', 'side', 'siege', 'sight', 'sign', 'silent', 'silk',
    'silly', 'silver', 'similar', 'simple', 'since', 'sing', 'siren', 'sister', 'situate', 'six', 'size',
    'skate', 'sketch', 'ski', 'skill', 'skin', 'skirt', 'skull', 'slab', 'slam', 'sleep', 'slender', 'slice',
    'slide', 'slight', 'slim', 'slogan', 'slot', 'slow', 'slush', 'small', 'smart', 'smile', 'smoke',
    'smooth', 'snack', 'snake', 'snap', 'sniff', 'snow', 'soap', 'soccer', 'social', 'sock', 'soda', 'soft',
    'solar', 'soldier', 'solid', 'solution', 'solve', 'someone', 'song', 'soon', 'sorry', 'sort', 'soul',
    'sound', 'soup', 'source', 'south', 'space', 'spare', 'spatial', 'spawn', 'speak', 'special', 'speed',
    'spell', 'spend', 'sphere', 'spice', 'spider', 'spike', 'spin', 'spirit', 'split', 'spoil', 'sponsor',
    'spoon', 'sport', 'spot', 'spray', 'spread', 'spring', 'spy', 'square', 'squeeze', 'squirrel', 'stable',
    'stadium', 'staff', 'stage', 'stairs', 'stamp', 'stand', 'start', 'state', 'stay', 'steak', 'steel',
    'stem', 'step', 'stereo', 'stick', 'still', 'sting', 'stock', 'stomach', 'stone', 'stool', 'story',
    'stove', 'strategy', 'street', 'strike', 'strong', 'struggle', 'student', 'stuff', 'stumble', 'style',
    'subject', 'submit', 'subway', 'success', 'such', 'sudden', 'suffer', 'sugar', 'suggest', 'suit',
    'summer', 'sun', 'sunny', 'sunset', 'super', 'supply', 'supreme', 'sure', 'surface', 'surge', 'surprise',
    'surround', 'survey', 'suspect', 'sustain', 'swallow', 'swamp', 'swap', 'swarm', 'swear', 'sweet',
    'swift', 'swim', 'swing', 'switch', 'sword', 'symbol', 'symptom', 'syrup', 'system', 'table', 'tackle',
    'tag', 'tail', 'talent', 'talk', 'tank', 'tape', 'target', 'task', 'taste', 'tattoo', 'taxi', 'teach',
    'team', 'tell', 'ten', 'tenant', 'tennis', 'tent', 'term', 'test', 'text', 'thank', 'that', 'theme',
    'then', 'theory', 'there', 'they', 'thing', 'this', 'thought', 'three', 'thrive', 'throw', 'thumb',
    'thunder', 'ticket', 'tide', 'tiger', 'tilt', 'timber', 'time', 'tiny', 'tip', 'tired', 'tissue',
    'title', 'toast', 'tobacco', 'today', 'toddler', 'toe', 'together', 'toilet', 'token', 'tomato',
    'tomorrow', 'tone', 'tongue', 'tonight', 'tool', 'tooth', 'top', 'topic', 'topple', 'torch', 'tornado',
    'tortoise', 'toss', 'total', 'tourist', 'toward', 'tower', 'town', 'toy', 'track', 'trade', 'traffic',
    'tragic', 'train', 'transfer', 'trap', 'trash', 'travel', 'tray', 'treat', 'tree', 'trend', 'trial',
    'tribe', 'trick', 'trigger', 'trim', 'trip', 'trophy', 'trouble', 'truck', 'true', 'truly', 'trumpet',
    'trust', 'truth', 'try', 'tube', 'tuition', 'tumble', 'tuna', 'tunnel', 'turkey', 'turn', 'turtle',
    'twelve', 'twenty', 'twice', 'twin', 'twist', 'two', 'type', 'typical', 'ugly', 'umbrella', 'unable',
    'unaware', 'uncle', 'uncover', 'under', 'undo', 'unfair', 'unfold', 'unhappy', 'uniform', 'unique',
    'unit', 'universe', 'unknown', 'unlock', 'until', 'unusual', 'unveil', 'update', 'upgrade', 'uphold',
    'upon', 'upper', 'upset', 'urban', 'urge', 'usage', 'use', 'used', 'useful', 'useless', 'usual',
    'utility', 'vacant', 'vacuum', 'vague', 'valid', 'valley', 'valve', 'van', 'vanish', 'vapor', 'various',
    'vast', 'vault', 'vehicle', 'velvet', 'vendor', 'venture', 'venue', 'verb', 'verify', 'version', 'very',
    'vessel', 'veteran', 'viable', 'vibrant', 'vicious', 'victory', 'video', 'view', 'village', 'vintage',
    'violin', 'virtual', 'virus', 'visa', 'visit', 'visual', 'vital', 'vivid', 'vocal', 'voice', 'void',
    'volcano', 'volume', 'vote', 'voyage', 'wage', 'wagon', 'wait', 'walk', 'wall', 'walnut', 'want',
    'warfare', 'warm', 'warrior', 'wash', 'wasp', 'waste', 'water', 'wave', 'way', 'wealth', 'weapon',
    'wear', 'weasel', 'weather', 'web', 'wedding', 'weekend', 'weird', 'welcome', 'west', 'wet', 'whale',
    'what', 'wheat', 'wheel', 'when', 'where', 'whip', 'whisper', 'wide', 'width', 'wife', 'wild', 'will',
    'win', 'window', 'wine', 'wing', 'wink', 'winner', 'winter', 'wire', 'wisdom', 'wise', 'wish', 'witness',
    'wolf', 'woman', 'wonder', 'wood', 'wool', 'word', 'work', 'world', 'worry', 'worth', 'wrap', 'wreck',
    'wrestle', 'wrist', 'write', 'wrong', 'yard', 'year', 'yellow', 'you', 'young', 'youth', 'zebra', 'zero',
    'zone', 'zoo',
)

# word -> index map for the BIP-39 parse; built once at import.
_WORD_INDEX = {word: index for index, word in enumerate(BIP39_WORDLIST)}

# Standard BIP-39 English-word mnemonic lengths (mirrors the Rust port's
# `SUPPORTED_WORD_COUNTS`). Any other word count is rejected by the parse.
SUPPORTED_WORD_COUNTS = (12, 15, 18, 21, 24)

# Maximum times a single word may repeat in an accepted mnemonic
# (decision C6). BIP-39 allows duplicates; a sequence where one word
# occurs 3+ times is not a plausible random draw.
MAX_WORD_REPEATS = 2

# Minimum distinct words per supported length (decision C6): the floor
# is `ceil(words / 3)`. Unsupported lengths are absent on purpose --
# `min_unique_words` yields 0 for them, because the word-count check in
# `_parse_mnemonic` gates those before the floor is ever consulted.
_MIN_UNIQUE_WORDS = {12: 4, 15: 5, 18: 6, 21: 7, 24: 8}

# Low-entropy warning threshold for the seed-reception policy (D-001,
# spec «Seed policy» R-6): when the `estimate_entropy` value of a phrase
# falls BELOW this many bits, reception prints a NON-blocking warning
# and continues in both modes (permissive and strict).
MIN_ENTROPY_WARNING_BITS = 128


class InsufficientEntropy(ValueError):
    """A checksum-valid mnemonic violates the C6 entropy floor.

    Raised by `validate_entropy` (and, through it, by `validate_seed`)
    when either C6 rule fails: too few distinct words for the phrase
    length, or a single word repeated more than `MAX_WORD_REPEATS`
    times. Subclasses `ValueError` so callers that only care about
    "bad seed" can catch the broader type.
    """


@require_kwargs_only
def min_unique_words(words: int = NotNone) -> int:
    """Minimum distinct words required for a mnemonic of `words` length
    (decision C6): `>= 4` of 12, `>= 5` of 15, `>= 6` of 18, `>= 7` of
    21, `>= 8` of 24 -- i.e. `ceil(words / 3)`.

    Contract: `words` is a phrase length (int). Returns the floor for
    the supported lengths and `0` for anything else -- an unsupported
    length never reaches this floor because `_parse_mnemonic` rejects
    the word count first, so 0 keeps `validate_entropy` vacuously
    permissive there instead of inventing a second gate.

    Mirrors the Rust port's `min_unique_words`.
    """
    return _MIN_UNIQUE_WORDS.get(words, 0)


@require_kwargs_only
def validate_entropy(words: Iterable[str] = NotNone) -> None:
    """Entropy-floor validation over mnemonic words (decision C6).

    Two rules, checked in order:
    1. distinct words >= `min_unique_words(len(words))`;
    2. no single word repeats more than `MAX_WORD_REPEATS` times
       (this subsumes the "all words identical" obvious-pattern case).

    Contract: `words` is any iterable of word strings (a generator is
    consumed into a list). Returns `None` when both rules pass; raises
    `InsufficientEntropy` with a human-readable rule violation
    otherwise. The distinct-word rule fires first, so a phrase failing
    both rules reports "distinct words". An empty word list is vacuously
    accepted -- the floor only ever sees non-empty lists from
    `validate_seed`, but the contract must not depend on that. Takes
    the words directly so the rules are testable without hunting for a
    checksum-valid mnemonic with a rare word pattern.

    Mirrors the Rust port's `validate_entropy`.
    """
    words = list(words)
    counts = {}
    for word in words:
        counts[word] = counts.get(word, 0) + 1
    floor = min_unique_words(words=len(words))
    unique = len(counts)
    if unique < floor:
        raise InsufficientEntropy(
            f'only {unique} distinct words, need at least {floor}')
    max_repeat = max(counts.values(), default=0)
    if max_repeat > MAX_WORD_REPEATS:
        word = max(counts, key=counts.get)
        raise InsufficientEntropy(
            f"word '{word}' repeats {max_repeat} times, max {MAX_WORD_REPEATS}")


@require_kwargs_only
def _parse_mnemonic(seed: str = NotNone) -> list:
    """Parse a BIP-39 English mnemonic and return its word list.

    The parse verifies, in order: word count against
    `SUPPORTED_WORD_COUNTS`, wordlist membership for every word, and
    the trailing checksum bits against the leading sha256(entropy)
    bits per the BIP-39 spec. The phrase is NFKD-normalised before
    splitting, mirroring the Rust port's `Mnemonic::parse_in`
    (`seed2bin` normalises the same way at KDF time).

    Contract: `seed` is the phrase as typed -- any unicode string;
    leading/trailing whitespace is ignored and words may be separated
    by runs of whitespace. Returns the parsed word list (its length is
    in `SUPPORTED_WORD_COUNTS`). Raises `ValueError` with a
    'BIP-39 mnemonic parse error: ...' message when any check fails;
    the common prefix groups every parse-stage failure the way the Rust
    port's `SeedError::Parse` does. Internal helper -- the public entry
    point is `validate_seed(strict=True)`, which layers the C6 entropy
    floor on top; the permissive mode never parses.
    """
    from unicodedata import normalize
    from hashlib import sha256
    words = normalize('NFKD', seed).split()
    if len(words) not in SUPPORTED_WORD_COUNTS:
        raise ValueError(
            f'BIP-39 mnemonic parse error: invalid word count {len(words)}: '
            f'must be 12, 15, 18, 21, or 24')
    try:
        indices = [_WORD_INDEX[word] for word in words]
    except KeyError as e:
        raise ValueError(
            f'BIP-39 mnemonic parse error: unknown word {e.args[0]!r}') from None
    bits = ''.join(format(index, '011b') for index in indices)
    checksum_bits = len(words) // 3
    entropy_bits = len(words) * 11 - checksum_bits
    entropy = int(bits[:entropy_bits], 2).to_bytes(entropy_bits // 8, 'big')
    expected = format(int.from_bytes(sha256(entropy).digest(), 'big'),
                      '0256b')[:checksum_bits]
    if bits[entropy_bits:] != expected:
        raise ValueError('BIP-39 mnemonic parse error: invalid checksum')
    return words


# Per-class charset sizes for the R-6 entropy estimate (spec «Seed
# policy» R-6): lowercase 26, uppercase 26, digits 10, space 1, other
# printable characters 33. Keys are the class names `estimate_entropy`
# classifies characters into; lowercase and uppercase are DISTINCT
# classes even though both weigh 26.
_ENTROPY_CLASS_WEIGHTS = {'lower': 26, 'upper': 26, 'digits': 10, 'space': 1, 'other': 33}


@require_kwargs_only
def estimate_entropy(phrase: str = NotNone) -> float:
    """Estimate the entropy of a user phrase in bits (D-001, spec R-6).

    The estimate is deliberately crude and character-class based:
    `bits = len(phrase) * log2(|charset|)`, where `|charset|` is the
    sum of `_ENTROPY_CLASS_WEIGHTS` over every character class PRESENT
    in the phrase -- lowercase 26, uppercase 26, digits 10, space 1,
    other printable characters 33 (the spec's catch-all row). This is
    NOT a security claim about the phrase's true entropy (a
    natural-language passphrase has far less); it only feeds the
    non-blocking R-6 warning at reception.

    Contract: `phrase` is any string. Returns the estimate in bits as
    a float; `0.0` for an empty phrase (no characters -> no entropy;
    reception rejects empty phrases before the estimate is consulted).
    Every character outside the four named classes -- including
    non-ASCII letters and control characters -- counts toward the
    "other" class, so the estimate stays defined for any input and no
    character is silently ignored.

    Single shared formula for every surface (CLI, TUI): callers must
    not re-implement the arithmetic locally.

    Mirrors the Rust port's `estimate_entropy`.
    """
    from math import log2
    present = set()
    for ch in phrase:
        if 'a' <= ch <= 'z':
            present.add('lower')
        elif 'A' <= ch <= 'Z':
            present.add('upper')
        elif '0' <= ch <= '9':
            present.add('digits')
        elif ch == ' ':
            present.add('space')
        else:
            present.add('other')
    charset = sum(_ENTROPY_CLASS_WEIGHTS[name] for name in present)
    if charset == 0:
        return 0.0
    return len(phrase) * log2(charset)


@require_kwargs_only
def entropy_warning(phrase: str = NotNone) -> 'str | None':
    """Non-blocking low-entropy warning for a user phrase (spec R-6).

    Computes `estimate_entropy` and compares against
    `MIN_ENTROPY_WARNING_BITS`. The comparison is strict: the warning
    fires only BELOW the threshold -- an estimate of exactly
    `MIN_ENTROPY_WARNING_BITS` bits is silent. The rule applies in
    BOTH reception modes (permissive and strict) and never blocks use;
    rejection is exclusively `validate_seed`'s job.

    Contract: `phrase` is any string. Returns the warning text -- one
    line with stable wording (pinned by tests) -- or `None` when the
    estimate is at or above the threshold. The text never contains any
    fragment of the phrase itself: seeds must not be echoed into
    warnings or logs. Callers print it prefixed (the CLI uses
    `warning: `) on stderr, keeping stdout machine-readable.

    Mirrors the Rust port's `entropy_warning`.
    """
    bits = estimate_entropy(phrase=phrase)
    if bits >= MIN_ENTROPY_WARNING_BITS:
        return None
    return (f'low seed entropy: estimated {bits:.1f} bits < '
            f'{MIN_ENTROPY_WARNING_BITS} bits; '
            f'consider a longer or more varied seed')


@require_kwargs_only
def validate_seed(seed: str = NotNone, strict: bool = False) -> None:
    """Validate a user-entered seed under the reception policy (D-001,
    spec «Seed policy» R-1…R-7).

    Two modes:
    - permissive (`strict=False`, the system default): accepts ANY
      non-empty phrase -- not only BIP-39 mnemonics. The BIP-39 parse
      and the C6 entropy floor are NOT applied (R-1).
    - strict (`strict=True`, CLI `--strict-bip39`): full BIP-39 parse
      (supported word count, wordlist membership, checksum) followed
      by the C6 entropy floor (`validate_entropy`). Any failure is a
      blocking refusal -- the wallet is not opened from such a phrase
      (R-4); a word count outside 12/15/18/21/24 is the same strict
      parse error, not a separate kind of refusal (R-5).

    In both modes an empty (after trim) phrase is an error (R-2); the
    check runs before the mode branch, so the error is identical in
    both.

    Contract: `seed` is the phrase as typed; `strict` selects the
    mode. Per the repo's kwargs-only convention the argument is passed
    explicitly at every call site -- the declared `False` documents
    the policy default (permissive), it is not a silently-fillable
    slot. Returns `None` when the phrase is accepted. Raises
    `ValueError` ('seed must not be empty') for an empty phrase in
    either mode; in strict mode additionally `ValueError`
    ('BIP-39 mnemonic parse error: ...') for a phrase that is not a
    valid BIP-39 mnemonic and `InsufficientEntropy` for one that
    parses but violates the entropy floor. Strict checks run before
    any KDF work. The R-6 low-entropy WARNING is never raised here --
    it is non-blocking; see `entropy_warning` and the CLI reception
    wiring.

    Mirrors the Rust port's `validate_seed` (post-D-001 split).
    """
    if not seed.strip():
        raise ValueError('seed must not be empty')
    if strict:
        words = _parse_mnemonic(seed=seed)
        validate_entropy(words=words)


# No require_kwargs_only on purpose: this is a callback-style predicate,
# invoked positionally by `_draw_until` -- same convention as the
# `on_address(tp, unspent)` callbacks in wallet/cli. The Rust port
# injects the equivalent as a plain closure `|m| ...`.
def _entropy_floor_rejects(words) -> bool:
    """Predicate form of `validate_entropy` for the redraw loop.

    Contract: `words` is a freshly drawn word list. Returns `True` when
    the draw violates the C6 floor (and must be redrawn), `False` when
    it passes. Exists as a named function because the redraw predicate
    must swallow `InsufficientEntropy` and answer a yes/no question --
    the same shape as the Rust port's injected
    `|m| validate_entropy(m.words()).is_err()` closure.
    """
    try:
        validate_entropy(words=words)
    except InsufficientEntropy:
        return True
    return False


@require_kwargs_only
def _draw_until(draw: Callable = NotNone, reject: Callable = NotNone):
    """Redraw from `draw` until `reject` accepts the value.

    Contract: `draw` is a zero-argument callable producing a fresh
    candidate; `reject` is a one-argument predicate returning `True`
    for values that must be redrawn. `draw` must be able to produce an
    accepting value -- with OS-RNG entropy a 15-of-2048 draw violates
    the C6 floor with probability ~1e-13, so the expected iteration
    count is ~1.00 and not terminating is probability-0. Returns the
    first accepted candidate. Split out with injected callables
    (mirroring the Rust port's `draw_until_unique`) so the retry arm is
    deterministically testable -- a real-entropy test cannot force a
    failing first draw.
    """
    value = draw()
    while reject(value):
        value = draw()
    return value


@require_kwargs_only
def _generate_seed(count: int = NotNone, allow_dups: bool = NotNone) -> list:
    """Draw `count` words from `BIP39_WORDLIST` -- the raw random draw.

    Contract: `count` is the number of words (at most 2048 when
    `allow_dups=False`); `allow_dups=True` samples WITH replacement
    (`random.choices`) and may return duplicates; `allow_dups=False`
    samples WITHOUT replacement (`random.sample`) and raises ValueError
    when `count` exceeds the wordlist. Returns the raw draw as a list;
    no entropy-floor filtering happens here -- `generate_seed` layers
    the C6 redraw on top so both draw branches stay independently
    testable.
    """
    from random import SystemRandom
    sysrandom = SystemRandom()
    if not allow_dups:
        return sysrandom.sample(BIP39_WORDLIST, count)
    return sysrandom.choices(BIP39_WORDLIST, k=count)


@require_kwargs_only
def generate_seed(count: int = NotNone, allow_dups: bool = NotNone) -> str:
    """Generate a fresh seed phrase: `count` BIP-39 words, space-joined.

    Contract: `count` is the number of words; `allow_dups=True` (the
    CLI default) samples with replacement and REDRAWS (decision C6)
    until the draw passes `validate_entropy`, so a generated seed can
    never violate the entropy floor right after being emitted -- redraws
    are extremely rare (a random 15-of-2048 draw violates the floor
    with probability ~1e-13). `allow_dups=False` samples without
    replacement: distinct words == count, so the floor is met by
    construction and no redraw can occur. Returns the seed as a single
    space-joined string. Mirrors the Rust port's `generate_seed` default
    (`unique = false`) path.

    Note: like the Rust port's default path, this does NOT produce a
    checksum-valid BIP-39 phrase -- the legacy KDF hashes the word
    string as-is, so `validate_seed` (full BIP-39 parse) does not apply
    to freshly generated seeds; only the entropy floor does.
    """
    if allow_dups:
        words = _draw_until(
            draw=lambda: _generate_seed(count=count, allow_dups=True),
            reject=_entropy_floor_rejects)
        return ' '.join(words)
    return ' '.join(_generate_seed(count=count, allow_dups=False))


@require_kwargs_only
def get_seed(echo: bool = NotNone) -> str:
    """Read the seed from the user.

    On a tty, the seed is read with `input()` (echoed) when `echo=True`;
    otherwise `getpass` is used and the seed stays silent. The flag
    lets the caller pick: the passphrase-aware path sets `echo=True`
    so the user sees what they're typing once a passphrase is in play,
    and the no-passphrase path sets `echo=False` (silent) because the
    seed alone is enough to spend the wallet.

    On a non-tty stdin (piped input, test fixtures) the read goes
    through `readline` regardless of `echo` -- a pipe never echoes the
    data back through this code path.
    """
    from sys import stdin
    if stdin.isatty():
        if echo:
            return input('seed: ')
        from getpass import getpass
        return getpass('seed: ')
    return stdin.readline().rstrip()


@require_kwargs_only
def get_passphrase(prompt: str = NotNone) -> str:
    """Prompt for an optional passphrase.

    Mirrors `get_seed`'s tty/non-tty split: on a tty the user types the
    passphrase silently (`getpass` echoes nothing); on a non-tty
    (piped input) the next line is read directly so scripts can drive
    the same flow with two `printf` lines.

    The passphrase is the BIP-39 "25th word": an empty string here is
    the legitimate "no passphrase" answer, so the helper returns `""`
    rather than refusing. The decision is recorded by the empty
    password going to `seed2bin` and taking the legacy branch -- nothing
    on disk, nothing in env, nothing in argv.
    """
    from sys import stdin
    if stdin.isatty():
        from getpass import getpass
        return getpass(prompt)
    return stdin.readline().rstrip('\n').rstrip('\r')


def get_seed_and_passphrase() -> tuple:
    """Prompt for the seed and the optional passphrase, in that order.

    The passphrase is asked first; an empty answer is the legitimate
    "no passphrase" choice and keeps the seed on the legacy KDF path
    (no PBKDF2 stretch). A non-empty answer routes the derivation
    through PBKDF2, which raises the cost of a brute-force attempt on
    a stolen seed+passphrase pair; in that case the seed is read with
    echo so the user can sanity-check what they typed. With an empty
    passphrase the seed is read silently (`getpass`), since the seed
    alone is enough to spend the wallet.

    On a non-tty stdin (piped input, tests) the read goes through
    `readline` either way -- a pipe never echoes through this code.

    Returns `(seed, passphrase)`. The passphrase is always a string
    and may be `""` -- the caller forwards it to `Wallet` and the KDF
    branches on emptiness.
    """
    passphrase = get_passphrase(prompt='passphrase (empty for none): ')
    # Passphrase set -> seed is shown (echo=True); passphrase empty ->
    # seed is silent (echo=False), since a visible seed alone is
    # enough to spend the wallet.
    seed = get_seed(echo=bool(passphrase))
    return seed, passphrase
