%%%-------------------------------------------------------------------
%%% @copyright (C) 2015, OnePipe Inc
%%% @doc
%%%
%%% Handle client requests for phone_number documents
%%%
%%% @end
%%% @contributors
%%%   David Singer
%%%-------------------------------------------------------------------
-module(wnm_voxbone).

-export([find_numbers/3
    ,acquire_number/1
    ,disconnect_number/1
    ,is_number_billable/1
    ,should_lookup_cnam/0
]).

-include("../wnm.hrl").

-define(WNM_VOXBONE_CONFIG_CAT, <<(?WNM_CONFIG_CAT)/binary, ".voxbone">>).

%%--------------------------------------------------------------------
%% @public
%% @doc
%% Query the Voxbone system for a quanity of available numbers
%% in a rate center
%% @end
%%--------------------------------------------------------------------
-spec find_numbers(ne_binary(), pos_integer(), wh_proplist()) ->
                          {'ok', wh_json:objects()} |
                          {'error', _}.
find_numbers(_Prefix, _Quantity, _Options) ->
    {'error', 'non_available'}.

-spec is_number_billable(wnm_number()) -> 'true'.
is_number_billable(_Number) -> 'true'.

%%--------------------------------------------------------------------
%% @public
%% @doc
%% Acquire a given number from the carrier
%% @end
%%--------------------------------------------------------------------
-spec acquire_number(wnm_number()) -> wnm_number().
acquire_number(#number{}=Number) ->
    Number.

%%--------------------------------------------------------------------
%% @public
%% @doc
%% Release a number from the routing table
%% @end
%%--------------------------------------------------------------------
-spec disconnect_number(wnm_number()) -> wnm_number().
disconnect_number(#number{}=Number) -> Number.

%%--------------------------------------------------------------------
%% @public
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec should_lookup_cnam() -> 'true'.
should_lookup_cnam() -> 'true'.
