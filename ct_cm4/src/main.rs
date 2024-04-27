#![no_std]
#![no_main]

// This example code models the use case for embedded firmware signature verification.

use cortex_m::asm;
use cortex_m_rt::entry;
use fips204::{ml_dsa_44::PublicKey, traits::{SerDes, Verifier}};
use hex_literal::hex;
use microbit::{board::Board, hal::{pac::DWT, prelude::OutputPin}};
use rtt_target::{rprintln, rtt_init_print};
//use panic_halt as _;
use panic_rtt_target as _;


const MESSAGE: [u8; 4] = *b"asdf";
const PUBLIC_KEY: [u8; 1312] = hex!("755193ec3402eb0e17947e6ed5605118967eb1200a28f9d8173097059141c57222978e92d50f3bf79c99f9cb0914d99847c35ff42c2d85a99abff46b4b344fb938e646f4ff1bfd80d090680682c1025129608e871af32ca533ce5c63f9ab4a897e739c84a356500e6ee02733ea3bd45ee57288cf9dbd9946ca7e0feebc47da5afc2974f5c58a3b48ab12689bac01e1d11c90b093a9ca231c68dfb3357eac610c36ff3da9ccdf79e382af9ed163d6e6e2dfa46c2b17f30386ca653fd3b689669f60ad8d29daee11c612ad5dede7859f4fd725b8ca847767d05abfee31070869b6b753634d1505034ee8c2e0fc1148cb857f59110f14c69afe8d72578680268d01b4bfc3479f3eebfe3820458e0f01fb5d6019936fc24bb4d2cceb0501d3bba9c6355708d1233867c201f0a77b560854ae4da538903e78116b248cfe1e438667f7e3d231b2ef21ea6c0c7543a80ac54a84e483ec7f9f4b12e151f0c3472bd241c972b32d1985d08cb2b1acc469cf9921c0e95018583af7f636796e4fe0616c44c0d6881097147a31d922b7fa9ba1ca906bf4bb15962d9c0e7aea69c144093ce6e9f7311548d346ba05bbbc24d3e299c48276a96cf28f05e146d9210009d76de1bffb9412c69011d029bad1a976224f8448a6243c3e791dbe809328eb50c7d3b2a67ea64bc28e06885842d18b8fa41ac099038ca9d243589a2b945db05db519bd202cccdd20cdad61b50f91b6213874337bcfe3c102cec4d86b8323ffec9570c2455f1a5bd978cb478c34b6799adddeb16554ff9512cead0a7861c22d6c9a764080e90b7395c84a39339712dd8084a31fc9e10f822cc976d71a2e1a67bd8288d0fb23174ea34521694dbc75fa4f13e3a1067b01d814779a9eb7732b1fc0b15d4dea15a9924bce53b31fd2cec142cd1a1c54911bab5ff71e6d700350ee445a08d3b127afc5856a6cb0b67d0563f8a5b4961f930e0634bceefc2a1072c2cf08f317d48533e93956d3ee42f4dbd94527a114ce09749f79a3d5d23c00870011b749c17ddbd4dbc8ef93f8a03d715a92e7f9213f4af4f501dc2d7aa967fee4379db783a17f6cd5c1d3fc0126236ca3fc23b74d0cec1f7439c1f5dae7bb06f44ca4a050a744101c2f1244b8f4f3d389e7c8b2cf558c5e4cce1a7ada441181c187cadcc1dbe1dfd95a295fdf4bfef9a3e818060b1e89d09ae09029d23baaa314c6d114f5be5300ef67a3c945ee6854712355ae7c9dbe8e54d43363daf2f6cc92d219783c580d4f026d80c93e401df20beef1de3e8804caf19133359a910cffceb708ec8b9acd1e717237d55ec62c86b66ed571fde9da48aa9b0f48e83b2145807c51c4c124e96a2229a876e3c42d90298a3c5f31d316a12145b66b550b52ab954657c413d41e8c2b6637f45d7d2338be0734c684ddc255b741d8e3b13f925e70f4270480d1e5b87ef64c0196f38c98fbd1b56ec2a38ec6e38ad0fff3eec32af25c4346a9feb232b1deabeb0e10bac63e07272b265a12718822efab2c805aa9f86b17041cfeca7c167faad7f8e3789b54a9be3b367e86cc8f392f8fea518bc714baeceddcc9a86a1dd1214e9df8c72d0f72e18ad4585da4550a4747d44a8c832fcc467f777ae4eb7fe7c361d8fe0bb72664df2e223c7491d01e709fa74254f6fdec386eddf4ffc9fefa706bfbeaedc350e156fe2af0de33935ba04934dc69ebb20f3c480caff6e91115f97a9510f9b03b1abe67366ff0afd9cf7d2f39e332e57162d0fdde642349f9b2248273f064a3bec19dbd9e75c01049b98ea673e1cca53994aa6ad06757f8a2f045775418ae9ccac497a3dd54ee26c194cdb53d2ac109648e98c4d931");
const SIGNATURE: [u8; 2420] = hex!("204e71dc783f063158152fdce71919c5d4e6c832f174bb4185a179dd228987f7a8cc5234eb918ae5cc6667b080bad306fa60de7729e002e2d84596456985a6fd2e2251b7b4d1ce3f5d52e319312c1bb1433f4d1009a15724a75f8a3aaeea98c7c5a64c017b931dd6927d682f0608ab72866a6f55dba1a2a44ba3cf76893cab7a989325f1717577cc2afe4becc5d5489b5cc83132956ee5f44069068fb27ee0eb404ab2fd97d87c2ea4133a8cb7b51d4870ad71f36c2086cbf9dae9943f674b02269b6542a91b455977d687c932473676dfebff831a3cffa9bea3742d0237ab25f14917541d136183717f2999860f48bf135f5fd0a0e3096e9a4e7fdf041673f476c4a97746a79aea11182033da6d46583446a56eec999dd894939380c164f64e9d2642a21a93c61b96e2e1a64a98f24fb4c1adf3a228e8c1cc8890fe62ce9bf2b9d9eb0c0a8b9257504626b0218e67af1902e25564617f936b9351a0de225964103b15b4acb52351ceed45f74520f2d9b4cd76fecfac78a0dcc1dfb4cada17e257a2559ccf4f68ff9ae15acc5033209a179e01d94fc3b0a4d52e5f3fac6ae487f10cc0ad07ecec8def6c7f356ea4ef08f479ed83db9b5c346af252a2624c6e51170620180f1296881a9ce5970acb4ce9dd8279f17d5dc5b65f367601ff941c0307bbf75761af428f2af32159e5516b397cfef7ae924faa07a63461a60f32c9027217f06e5bba3bf8f82621b5ee5393a405609dcfc3580602391eee890bb27112da6981acb1a7bfdba5b1a46cdb315b5d7f6f3bf20346d3016e9d964ac81e3481f5f7848e2df803075f9bca43cfa61758480a45f90a9dd281c9ec3d707762d83da6dcb321d57cbbdde3e1bdde8834ce3613ad999d3e007b7358e45611ff3995edf5e90125521763f9ec10930cd7c11a0154c8d58a68fb891f210e0aac24f9e72061a29ed74c5f70e71ac6f9427f68959f062bb90af17d6ce1521d52674d2762fff239365094f84f95929ca690c7f4d8f6bf1d76ba7372ee9f98315fc26593ea4367434440004c117c85ac833d9be51d5410f1c3a644adb104268b94e2418735fb645d73351ef5f480dd1f4ff1623f479d6fae6cdacf5075f971e81bc218850da40695f47d3c392fd23657f70a5cc9fa394ab7b5c2622ea4949210435ecc29878ca4a582af0a977a5947003f03bcbdcebe25ed395468480da9c155b02e4a42094fbda5068ad21890c03bac7a1e55e67a9c79a0f5458075f6b602b51b1ab223a5206193770d0170a3d39870abdb5f5fc948071ecc81b6201eb76e1b68f0f2838b0e2a9413273a19ba44f097c13a452b6b5dcbae603cdec3e4a8657924d813e190b0c7f18e77f2ff1ff51bc263bea49dc190a667d581264614594a57910376215f9bee23261e08b82242d20a087c1cc6d11ad27d4d613bc5f61177924946a9b7d45020e643f5a66d032b42e7fff9a462a778b447993158c9561c830db561a4e92453523e605ca229fc4458356effa93dc64e8f4d659392bc9b3e291342eba8cff9b97344e11f6ad14f69335fc48eda49f1ebcb4fbe2c40657eb8628a1ed21924e676f2019e868bdcbc24b318e74aa4533ab28b5c56386e905fd92e4fc80d10e98b586cce1c4c9c6bf8fcc02c4b99e9e43153a2652cbaae0f6e53c15eff93b0099548a2c3a8a9e1e4186874a083ec981f94ace4da1ea3ad0500173de9d9e15fed94975152cf5fd07e46c41e7207799e13b7b1a01e7895dfde5ba81e45b5f0529154b152d2a98c149f2ada55cd6f05823ae0ecac0e174dab9ba7979e793e65a024994007a50a3739ad4a9511f5af1d46fe3701014d46e7e9da21c27aabcbc13438bbf5fbc2f60073bbf71bb7ccefed210eb621557345cc53c1a631117da74b3df288d30004ba10c1d0bf7ce30acd706c6acc65b5bb6e7a550f93c3529453fa4811d18a4117700267c501c202f3de0e55a72afb5f592efe4cbffb0e3c686086ca253fe38a4349b39b94f40b60b64c7b34b1657550f2ccecad18d0ade2212b46edeff7c63dc30bd3d6d248e083f10f3e156e7bdf4b6ccee2a577ed98317c34f8b987b6d1f8458496fea46c7df8cf29bc32bbf76294698b115c999fe9f50d18c2ca451fc356392cb6553af5f78d4b816aeabdc392b33638fc2f12ada1bdd403978a65c370bd98225af3febd978393d92c73a419ee78542adfb6a452e3eea0d0d5a5ad332a14c7c98219c5b8566e0ce1a7bb473a105e7dba3d2829f8bd6e2eda5a98f1b609698ea1dd0f2eed00cdc5cbc2912fe7b98f7fde7f9bf795b0c2a5e49cee77c9d2caa4e408ee964137b0ec192dfbf04c32fa7ac0b9ad682dcdda249a17c2c2b1f664cf3d877aa9619a44b6dfbd5a75738fbb40ecd0d753f8d4cd753cf2f6bb2cee52c6875bef04a887ddf8dab3173c208f1f7a370cf2514fd807e316c86f4f54e98b42313e5e8a508f1957d5c6a54c4e4f7e53da8911163c87c2d3fdf66b2642428db4cc13de10aedbd431e9306f12fdf95e88d163fdd93f30330611e3fa277a606013c3c9cb16cedddb3183757f450d530f263d22a765c3afb027664353d5879605cfc5e673a728b975161835bbc85e274edcf6b071bd5fde7d6fa80ffea0bf124bf72ae642adab1b0ec6c6247f462d32622ea63df8322fe5e966e7701c6783df9642d98ca1026852f91fb04fea69ae521bfde282cf39ae3c02e368f5e3aab180ce736fb22330e26fd91c767e0789ba9b356d59bb55112f9c438dc049adf69278edfa504da7cb5c291efc76f1d22c81f50a1edc1fa9e841b55599e0ea09dd0b63da47073e7fa7afa0e3a5f5f4ce778aab7cbd0ce54b5c105ffc405ca3482274fd64a14caf1db94bce36d95714eb416f6ce8a2a02067bb0ebe925587592c1ead49c22a16cef7386f1a94335d7c5d9383293b7d47fc9108d971856c35d834f369bedc555ffb5573f286ca30325e319c9a6b59207b51f1ea2f57197a01b9d1f7e9b8f70690eaeb07b104f94dd9870e493bd6909e5efd0894788e8b9f5c6d615b96f46a06457cb88a4befffd15c882953a6b265618443a8fec0fe2977cc871dc400a2d352afb7d82f2fd5d87bb19dbea8eae0a137885ad98d10e0412e698524e646061706b697b464977fb016331429e8e788e59c63ffb985d87cce0cbe9db668bb866e729f7f85de173d3c34d1eed790ad8ea0f54a86a222ed012a36320fa3a79c4f4c9c996996f28e422f4ff5e2fd6d1c5c94933f1965a4a71dda50dc75f1b5343d1ba5d7b0d66fc31d0fc050f65689636b335634315ea2bf23d870b1b386aa57c80c0d3f60657bccd1d621283f5a6590aab7c9d8ecf72a31414b5764798698b7c1d1dce3060b1130343e5376788ca1d8f6fb0000000000000000000000000000000000000000000000000000000000000009152331");


#[entry]
fn main() -> ! {
    let mut board = Board::take().unwrap();
    board.DCB.enable_trace();
    board.DWT.enable_cycle_counter();
    board.display_pins.col1.set_low().unwrap();
    rtt_init_print!();

    let mut i = 0u32;
    let pk = PublicKey::try_from_bytes(PUBLIC_KEY).unwrap();
    //let (_pk, _sk) = ml_dsa_44::KG::try_keygen_with_rng_vt(&mut my_rng).unwrap();
    //let _res = sk.try_sign_with_rng_ct(&mut my_rng, &message);

    loop {
        if (i % 10) == 0 { board.display_pins.row1.set_high().unwrap(); };
        if (i % 10) == 5 { board.display_pins.row1.set_low().unwrap(); };
        i += 1;

        asm::isb();
        let start = DWT::cycle_count();
        asm::isb();

        assert!(pk.try_verify_vt(&MESSAGE, &SIGNATURE).unwrap()); // Use the public to verify message signature

        asm::isb();
        let finish = DWT::cycle_count();
        asm::isb();

        let count = finish - start;
        rprintln!("Cycle count: {}", count);
    }
}
