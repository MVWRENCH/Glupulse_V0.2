--
-- PostgreSQL database dump
--

-- Dumped from database version 18.0 (Debian 18.0-1.pgdg13+3)
-- Dumped by pg_dump version 18.0 (Homebrew)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: activity_activity_intensity; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.activity_activity_intensity AS ENUM (
    'Low',
    'Medium',
    'High'
);


ALTER TYPE public.activity_activity_intensity OWNER TO postgres;

--
-- Name: chat_conversations_participant1_type; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.chat_conversations_participant1_type AS ENUM (
    'user',
    'seller',
    'doctor'
);


ALTER TYPE public.chat_conversations_participant1_type OWNER TO postgres;

--
-- Name: chat_conversations_participant2_type; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.chat_conversations_participant2_type AS ENUM (
    'user',
    'seller',
    'doctor'
);


ALTER TYPE public.chat_conversations_participant2_type OWNER TO postgres;

--
-- Name: chat_messages_sender_type; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.chat_messages_sender_type AS ENUM (
    'user',
    'seller',
    'doctor'
);


ALTER TYPE public.chat_messages_sender_type OWNER TO postgres;

--
-- Name: doctor_appointments_appointment_status; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.doctor_appointments_appointment_status AS ENUM (
    'scheduled',
    'confirmed',
    'completed',
    'cancelled',
    'rescheduled',
    'no_show'
);


ALTER TYPE public.doctor_appointments_appointment_status OWNER TO postgres;

--
-- Name: doctor_appointments_appointment_type; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.doctor_appointments_appointment_type AS ENUM (
    'video_call',
    'chat',
    'in_person',
    'phone_call'
);


ALTER TYPE public.doctor_appointments_appointment_type OWNER TO postgres;

--
-- Name: seller_promotions_promotion_type; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.seller_promotions_promotion_type AS ENUM (
    'percentage',
    'fixed_amount'
);


ALTER TYPE public.seller_promotions_promotion_type OWNER TO postgres;

--
-- Name: seller_seller_status; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.seller_seller_status AS ENUM (
    'active',
    'inactive',
    'suspended'
);


ALTER TYPE public.seller_seller_status OWNER TO postgres;

--
-- Name: user_cart_cart_status; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.user_cart_cart_status AS ENUM (
    'active',
    'purchased',
    'deleted',
    ''
);


ALTER TYPE public.user_cart_cart_status OWNER TO postgres;

--
-- Name: user_order_order_status; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.user_order_order_status AS ENUM (
    'Processing',
    'Shipped',
    'Delivered',
    'Rejected',
    'Cancelled'
);


ALTER TYPE public.user_order_order_status OWNER TO postgres;

--
-- Name: user_order_payment_status; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.user_order_payment_status AS ENUM (
    'Pending',
    'Paid',
    'Failed'
);


ALTER TYPE public.user_order_payment_status OWNER TO postgres;

--
-- Name: user_transaction_payment_status; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.user_transaction_payment_status AS ENUM (
    'Pending',
    'Success',
    'Failed',
    'Expired'
);


ALTER TYPE public.user_transaction_payment_status OWNER TO postgres;

--
-- Name: user_vip_vip_status; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.user_vip_vip_status AS ENUM (
    'Pending',
    'Active',
    'Expired'
);


ALTER TYPE public.user_vip_vip_status OWNER TO postgres;

--
-- Name: users_user_gender; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.users_user_gender AS ENUM (
    'Male',
    'Female'
);


ALTER TYPE public.users_user_gender OWNER TO postgres;

--
-- Name: ensure_one_default_address(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.ensure_one_default_address() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    -- ...
    -- If setting a new default, unset others
    IF NEW.is_default = true THEN
        UPDATE user_addresses 
        SET is_default = false 
        WHERE user_id = NEW.user_id 
        AND address_id != NEW.address_id 
        AND is_default = true;
    END IF;
    
    RETURN NEW;
END;
$$;


ALTER FUNCTION public.ensure_one_default_address() OWNER TO postgres;

--
-- Name: on_update_current_timestamp_chat_conversations(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.on_update_current_timestamp_chat_conversations() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
   NEW.last_message_at = now();
   RETURN NEW;
END;
$$;


ALTER FUNCTION public.on_update_current_timestamp_chat_conversations() OWNER TO postgres;

--
-- Name: on_update_current_timestamp_delivery_orders(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.on_update_current_timestamp_delivery_orders() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
   NEW.updated_at = now();
   RETURN NEW;
END;
$$;


ALTER FUNCTION public.on_update_current_timestamp_delivery_orders() OWNER TO postgres;

--
-- Name: on_update_current_timestamp_doctor_appointments(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.on_update_current_timestamp_doctor_appointments() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
   NEW.updated_at = now();
   RETURN NEW;
END;
$$;


ALTER FUNCTION public.on_update_current_timestamp_doctor_appointments() OWNER TO postgres;

--
-- Name: on_update_current_timestamp_doctor_consultation_records(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.on_update_current_timestamp_doctor_consultation_records() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
   NEW.updated_at = now();
   RETURN NEW;
END;
$$;


ALTER FUNCTION public.on_update_current_timestamp_doctor_consultation_records() OWNER TO postgres;

--
-- Name: on_update_current_timestamp_glucose_manual(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.on_update_current_timestamp_glucose_manual() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
   NEW.glucose_inputdate = now();
   RETURN NEW;
END;
$$;


ALTER FUNCTION public.on_update_current_timestamp_glucose_manual() OWNER TO postgres;

--
-- Name: on_update_current_timestamp_seller_promotions(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.on_update_current_timestamp_seller_promotions() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
   NEW.updated_at = now();
   RETURN NEW;
END;
$$;


ALTER FUNCTION public.on_update_current_timestamp_seller_promotions() OWNER TO postgres;

--
-- Name: update_address_updated_at(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.update_address_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$;


ALTER FUNCTION public.update_address_updated_at() OWNER TO postgres;

--
-- Name: update_updated_at_column(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.update_updated_at_column() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.user_updated_at_auth = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$;


ALTER FUNCTION public.update_updated_at_column() OWNER TO postgres;

--
-- Name: update_user_addresses_updated_at(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.update_user_addresses_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;


ALTER FUNCTION public.update_user_addresses_updated_at() OWNER TO postgres;

--
-- Name: verify_otp_atomic(uuid, integer); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.verify_otp_atomic(p_entity_id uuid, p_max_attempts integer) RETURNS TABLE(secret text, is_valid boolean, attempts integer, status text)
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_record RECORD;
BEGIN
    -- Single atomic operation
    UPDATE otp_codes
    SET otp_attempts = CASE 
        WHEN expires_at < NOW() THEN otp_attempts  -- Don't increment if expired
        WHEN otp_attempts >= p_max_attempts THEN otp_attempts
        ELSE otp_attempts + 1
    END
    WHERE entity_id = p_entity_id
    RETURNING 
        otp_secret,
        otp_attempts,
        expires_at,
        otp_id
    INTO v_record;
    
    IF NOT FOUND THEN
        -- Return dummy data for not found
        RETURN QUERY SELECT 
            ''::TEXT as secret,
            FALSE as is_valid,
            0 as attempts,
            'not_found'::TEXT as status;
        RETURN;
    END IF;
    
    -- Check conditions
    IF v_record.expires_at < NOW() THEN
        RETURN QUERY SELECT 
            v_record.otp_secret,
            FALSE,
            v_record.otp_attempts,
            'expired'::TEXT;
    ELSIF v_record.otp_attempts > p_max_attempts THEN
        -- Delete on max attempts
        DELETE FROM otp_codes WHERE otp_id = v_record.otp_id;
        RETURN QUERY SELECT 
            v_record.otp_secret,
            FALSE,
            v_record.otp_attempts,
            'max_attempts'::TEXT;
    ELSE
        RETURN QUERY SELECT 
            v_record.otp_secret,
            TRUE,
            v_record.otp_attempts,
            'active'::TEXT;
    END IF;
END;
$$;


ALTER FUNCTION public.verify_otp_atomic(p_entity_id uuid, p_max_attempts integer) OWNER TO postgres;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: activity; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.activity (
    activity_id character varying(10) NOT NULL,
    activity_categoryid character varying(10) DEFAULT NULL::character varying,
    activity_name character varying(50) NOT NULL,
    activity_duration integer,
    activity_caloriesperminute double precision,
    activity_intensity public.activity_activity_intensity,
    activity_information character varying(255) DEFAULT NULL::character varying,
    activity_picturepath character varying(255) DEFAULT NULL::character varying
);


ALTER TABLE public.activity OWNER TO postgres;

--
-- Name: activity_categories; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.activity_categories (
    activity_categoryid character varying(10) NOT NULL,
    activity_category character varying(30) DEFAULT NULL::character varying,
    activity_categorydescription text
);


ALTER TABLE public.activity_categories OWNER TO postgres;

--
-- Name: activity_recommendation_items; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.activity_recommendation_items (
    item_id character varying(30) NOT NULL,
    recommendation_id character varying(30) NOT NULL,
    activity_id character varying(10) DEFAULT NULL::character varying,
    timestamp_date timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE public.activity_recommendation_items OWNER TO postgres;

--
-- Name: activity_recommendations; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.activity_recommendations (
    recommendation_id character varying(30) NOT NULL,
    user_id character varying(20) NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE public.activity_recommendations OWNER TO postgres;

--
-- Name: chat_conversations; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.chat_conversations (
    conversation_id character varying(60) NOT NULL,
    participant1_id character varying(20) NOT NULL,
    participant1_type public.chat_conversations_participant1_type NOT NULL,
    participant2_id character varying(20) NOT NULL,
    participant2_type public.chat_conversations_participant2_type NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    last_message_at timestamp with time zone
);


ALTER TABLE public.chat_conversations OWNER TO postgres;

--
-- Name: chat_messages; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.chat_messages (
    message_id character varying(70) NOT NULL,
    conversation_id character varying(60) NOT NULL,
    sender_id bigint NOT NULL,
    sender_type public.chat_messages_sender_type NOT NULL,
    message_content text NOT NULL,
    sent_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    is_read boolean DEFAULT false
);


ALTER TABLE public.chat_messages OWNER TO postgres;

--
-- Name: doctor; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.doctor (
    doctor_id character varying(20) NOT NULL,
    doctor_username character varying(30) NOT NULL,
    doctor_password character varying(255) NOT NULL,
    doctor_firstname character varying(50) NOT NULL,
    doctor_lastname character varying(50) DEFAULT NULL::character varying,
    doctor_email character varying(100) NOT NULL,
    doctor_phonenumber character varying(15) NOT NULL,
    doctor_specialist character varying(50) DEFAULT NULL::character varying,
    doctor_sip character varying(30) DEFAULT NULL::character varying,
    doctor_province character varying(50) DEFAULT NULL::character varying,
    doctor_city character varying(50) DEFAULT NULL::character varying,
    doctor_district character varying(50) DEFAULT NULL::character varying,
    doctor_gmapslink character varying(500) DEFAULT NULL::character varying,
    doctor_practiceaddress character varying(255) DEFAULT NULL::character varying,
    doctor_practiceschedule text,
    doctor_accountstatus boolean DEFAULT true NOT NULL,
    doctor_photopath character varying(255) DEFAULT NULL::character varying
);


ALTER TABLE public.doctor OWNER TO postgres;

--
-- Name: doctor_appointments; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.doctor_appointments (
    appointment_id bigint NOT NULL,
    user_id character varying(20) NOT NULL,
    doctor_id character varying(20) NOT NULL,
    appointment_datetime timestamp with time zone NOT NULL,
    appointment_status public.doctor_appointments_appointment_status DEFAULT 'scheduled'::public.doctor_appointments_appointment_status NOT NULL,
    appointment_type public.doctor_appointments_appointment_type NOT NULL,
    appointment_reason text,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone
);


ALTER TABLE public.doctor_appointments OWNER TO postgres;

--
-- Name: doctor_appointments_appointment_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.doctor_appointments_appointment_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.doctor_appointments_appointment_id_seq OWNER TO postgres;

--
-- Name: doctor_appointments_appointment_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.doctor_appointments_appointment_id_seq OWNED BY public.doctor_appointments.appointment_id;


--
-- Name: doctor_availability; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.doctor_availability (
    availability_id bigint NOT NULL,
    doctor_id character varying(20) NOT NULL,
    day_of_week character varying(50) NOT NULL,
    start_time time without time zone NOT NULL,
    end_time time without time zone NOT NULL
);


ALTER TABLE public.doctor_availability OWNER TO postgres;

--
-- Name: doctor_availability_availability_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.doctor_availability_availability_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.doctor_availability_availability_id_seq OWNER TO postgres;

--
-- Name: doctor_availability_availability_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.doctor_availability_availability_id_seq OWNED BY public.doctor_availability.availability_id;


--
-- Name: doctor_consultation_records; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.doctor_consultation_records (
    record_id bigint NOT NULL,
    appointment_id bigint NOT NULL,
    doctor_notes text,
    doctor_diagnosis text,
    next_consultation boolean DEFAULT false,
    next_consultation_date date,
    recorded_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone
);


ALTER TABLE public.doctor_consultation_records OWNER TO postgres;

--
-- Name: doctor_consultation_records_record_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.doctor_consultation_records_record_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.doctor_consultation_records_record_id_seq OWNER TO postgres;

--
-- Name: doctor_consultation_records_record_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.doctor_consultation_records_record_id_seq OWNED BY public.doctor_consultation_records.record_id;


--
-- Name: doctor_reviews; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.doctor_reviews (
    review_id bigint NOT NULL,
    doctor_id character varying(20) NOT NULL,
    user_id character varying(20) NOT NULL,
    review_rating smallint NOT NULL,
    review_comment text,
    review_date timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE public.doctor_reviews OWNER TO postgres;

--
-- Name: doctor_reviews_review_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.doctor_reviews_review_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.doctor_reviews_review_id_seq OWNER TO postgres;

--
-- Name: doctor_reviews_review_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.doctor_reviews_review_id_seq OWNED BY public.doctor_reviews.review_id;


--
-- Name: food_category; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.food_category (
    food_categoryid character varying(10) NOT NULL,
    food_category character varying(30) NOT NULL
);


ALTER TABLE public.food_category OWNER TO postgres;

--
-- Name: food_picture; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.food_picture (
    photo_id bigint NOT NULL,
    food_id character varying(20) DEFAULT NULL::character varying,
    food_photopath character varying(255) DEFAULT NULL::character varying,
    food_photodescription character varying(100) DEFAULT NULL::character varying
);


ALTER TABLE public.food_picture OWNER TO postgres;

--
-- Name: food_picture_photo_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.food_picture_photo_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.food_picture_photo_id_seq OWNER TO postgres;

--
-- Name: food_picture_photo_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.food_picture_photo_id_seq OWNED BY public.food_picture.photo_id;


--
-- Name: food_recommendation; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.food_recommendation (
    recommendation_id character varying(40) NOT NULL,
    user_id character varying(20) NOT NULL,
    generated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    notes text,
    source_agent character varying(50) DEFAULT NULL::character varying
);


ALTER TABLE public.food_recommendation OWNER TO postgres;

--
-- Name: foods; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.foods (
    food_id uuid DEFAULT gen_random_uuid() NOT NULL,
    seller_id uuid NOT NULL,
    food_name text NOT NULL,
    description text,
    price numeric(10,2) NOT NULL,
    currency character varying(3) DEFAULT 'IDR'::character varying NOT NULL,
    photo_url text,
    thumbnail_url text,
    is_available boolean DEFAULT true,
    stock_count integer DEFAULT '-1'::integer,
    tags text[],
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    serving_size_g numeric(10,2),
    calories numeric(10,2),
    protein_g numeric(10,2),
    fat_g numeric(10,2),
    carbohydrate_g numeric(10,2),
    dietary_fiber_g numeric(10,2),
    sugars_g numeric(10,2),
    saturated_fat_g numeric(10,2),
    polyunsaturated_fat_g numeric(10,2),
    monounsaturated_fat_g numeric(10,2),
    trans_fat_g numeric(10,2),
    cholesterol_mg numeric(10,2),
    sodium_mg numeric(10,2),
    potassium_mg numeric(10,2),
    water_g numeric(10,2),
    vitamin_a_mcg numeric(10,2),
    vitamin_c_mg numeric(10,2),
    vitamin_d_mcg numeric(10,2),
    vitamin_e_mg numeric(10,2),
    vitamin_k_mcg numeric(10,2),
    thiamin_mg numeric(10,2),
    riboflavin_mg numeric(10,2),
    niacin_mg numeric(10,2),
    vitamin_b5_mg numeric(10,2),
    vitamin_b6_mg numeric(10,2),
    folate_mcg numeric(10,2),
    vitamin_b12_mcg numeric(10,2),
    calcium_mg numeric(10,2),
    copper_mg numeric(10,2),
    iron_mg numeric(10,2),
    magnesium_mg numeric(10,2),
    manganese_mg numeric(10,2),
    phosphorus_mg numeric(10,2),
    selenium_mcg numeric(10,2),
    zinc_mg numeric(10,2),
    caffeine_mg numeric(10,2),
    nutrition_density numeric(10,2)
);


ALTER TABLE public.foods OWNER TO postgres;

--
-- Name: logs_auth; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.logs_auth (
    log_id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id character varying(255),
    log_category character varying(50) NOT NULL,
    log_action character varying(100) NOT NULL,
    log_message text NOT NULL,
    log_level character varying(20) DEFAULT 'info'::character varying,
    ip_address inet,
    user_agent text,
    metadata jsonb,
    created_at timestamp with time zone DEFAULT now()
);


ALTER TABLE public.logs_auth OWNER TO postgres;

--
-- Name: message_attachments; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.message_attachments (
    attachment_id bigint NOT NULL,
    message_id character varying(70) NOT NULL,
    file_url character varying(512) NOT NULL,
    file_type character varying(100) NOT NULL,
    file_name character varying(255) DEFAULT NULL::character varying,
    file_size_bytes bigint,
    uploaded_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE public.message_attachments OWNER TO postgres;

--
-- Name: message_attachments_attachment_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.message_attachments_attachment_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.message_attachments_attachment_id_seq OWNER TO postgres;

--
-- Name: message_attachments_attachment_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.message_attachments_attachment_id_seq OWNED BY public.message_attachments.attachment_id;


--
-- Name: otp_codes; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.otp_codes (
    otp_id uuid DEFAULT gen_random_uuid() NOT NULL,
    entity_id uuid NOT NULL,
    entity_role character varying(20) NOT NULL,
    otp_secret text NOT NULL,
    otp_purpose character varying(50) NOT NULL,
    otp_attempts integer DEFAULT 0 NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    deletion_scheduled_at timestamp with time zone,
    CONSTRAINT otp_codes_entity_role_check CHECK (((entity_role)::text = ANY ((ARRAY['user'::character varying, 'doctor'::character varying, 'seller'::character varying])::text[])))
);


ALTER TABLE public.otp_codes OWNER TO postgres;

--
-- Name: pending_registrations; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.pending_registrations (
    pending_id uuid DEFAULT gen_random_uuid() NOT NULL,
    entity_role character varying(20) NOT NULL,
    email character varying(255) NOT NULL,
    username character varying(100),
    hashed_password text NOT NULL,
    first_name text,
    last_name text,
    raw_data jsonb,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT pending_registrations_entity_role_check CHECK (((entity_role)::text = ANY ((ARRAY['user'::character varying, 'doctor'::character varying, 'seller'::character varying])::text[])))
);


ALTER TABLE public.pending_registrations OWNER TO postgres;

--
-- Name: seller_profiles; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.seller_profiles (
    seller_username character varying(50) CONSTRAINT seller_seller_username_not_null NOT NULL,
    seller_password character varying(255) CONSTRAINT seller_seller_password_not_null NOT NULL,
    seller_name character varying(50) CONSTRAINT seller_seller_name_not_null NOT NULL,
    seller_businessname character varying(50) CONSTRAINT seller_seller_businessname_not_null NOT NULL,
    seller_email character varying(50) CONSTRAINT seller_seller_email_not_null NOT NULL,
    seller_phonenumber bigint CONSTRAINT seller_seller_phonenumber_not_null NOT NULL,
    seller_province character varying(50) DEFAULT NULL::character varying,
    seller_city character varying(50) DEFAULT NULL::character varying,
    seller_district character varying(50) DEFAULT NULL::character varying,
    seller_gmapslink character varying(50) DEFAULT NULL::character varying,
    seller_lat character varying(50) DEFAULT NULL::character varying,
    seller_long character varying(50) DEFAULT NULL::character varying,
    seller_address text CONSTRAINT seller_seller_address_not_null NOT NULL,
    seller_logopath text,
    seller_bannerpath character varying(255) DEFAULT NULL::character varying,
    seller_joindate date DEFAULT CURRENT_TIMESTAMP,
    seller_status public.seller_seller_status DEFAULT 'active'::public.seller_seller_status,
    seller_id uuid CONSTRAINT seller_seller_id_not_null NOT NULL
);


ALTER TABLE public.seller_profiles OWNER TO postgres;

--
-- Name: user_addresses; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.user_addresses (
    address_id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id text NOT NULL,
    address_line1 text NOT NULL,
    address_line2 text,
    address_city text NOT NULL,
    address_province text,
    address_postalcode text,
    address_latitude double precision,
    address_longitude double precision,
    address_label text DEFAULT 'Home'::text NOT NULL,
    recipient_name text,
    recipient_phone text,
    delivery_notes text,
    is_default boolean DEFAULT false NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.user_addresses OWNER TO postgres;

--
-- Name: user_cart_items; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.user_cart_items (
    cart_item_id uuid DEFAULT gen_random_uuid() CONSTRAINT cart_items_cart_item_id_not_null NOT NULL,
    cart_id uuid CONSTRAINT cart_items_cart_id_not_null NOT NULL,
    food_id uuid CONSTRAINT cart_items_food_id_not_null NOT NULL,
    quantity integer CONSTRAINT cart_items_quantity_not_null NOT NULL,
    CONSTRAINT cart_items_quantity_check CHECK ((quantity > 0))
);


ALTER TABLE public.user_cart_items OWNER TO postgres;

--
-- Name: user_carts; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.user_carts (
    cart_id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id text NOT NULL,
    seller_id uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.user_carts OWNER TO postgres;

--
-- Name: user_email_change_requests; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.user_email_change_requests (
    request_id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id character varying(100) NOT NULL,
    new_email character varying(255) NOT NULL,
    verification_token text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.user_email_change_requests OWNER TO postgres;

--
-- Name: user_order_items; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.user_order_items (
    order_item_id uuid DEFAULT gen_random_uuid() NOT NULL,
    order_id uuid NOT NULL,
    food_id uuid NOT NULL,
    quantity integer NOT NULL,
    price_at_purchase numeric(10,2) NOT NULL,
    food_name_snapshot text NOT NULL
);


ALTER TABLE public.user_order_items OWNER TO postgres;

--
-- Name: user_orders; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.user_orders (
    order_id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id text NOT NULL,
    seller_id uuid NOT NULL,
    total_price numeric(10,2) NOT NULL,
    status character varying(50) DEFAULT 'pending'::character varying NOT NULL,
    delivery_address_json jsonb NOT NULL,
    payment_status character varying(50) DEFAULT 'unpaid'::character varying NOT NULL,
    payment_method character varying(50),
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.user_orders OWNER TO postgres;

--
-- Name: users; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.users (
    user_id character varying(100) NOT NULL,
    user_username character varying(50),
    user_password character varying(255),
    user_firstname character varying(50),
    user_lastname character varying(50) DEFAULT NULL::character varying,
    user_email character varying(100),
    user_dob date,
    user_gender public.users_user_gender,
    user_accounttype smallint DEFAULT '0'::smallint,
    user_name_auth character varying(255),
    user_avatar_url text,
    user_provider character varying(50),
    user_provider_user_id character varying(255),
    user_raw_data jsonb,
    user_created_at_auth timestamp with time zone,
    user_updated_at_auth timestamp with time zone,
    user_last_login_at timestamp with time zone,
    user_email_auth character varying(255),
    is_email_verified boolean DEFAULT false,
    email_verified_at timestamp with time zone
);


ALTER TABLE public.users OWNER TO postgres;

--
-- Name: TABLE users; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON TABLE public.users IS 'Unified user table supporting both traditional username/password and OAuth authentication';


--
-- Name: COLUMN users.user_username; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.users.user_username IS 'Username for traditional auth (NULL for OAuth-only users)';


--
-- Name: COLUMN users.user_password; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.users.user_password IS 'Hashed password for traditional auth (NULL for OAuth-only users)';


--
-- Name: COLUMN users.user_email; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.users.user_email IS 'Primary email (used for both auth types)';


--
-- Name: COLUMN users.user_provider; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.users.user_provider IS 'OAuth provider name (google, facebook, etc.) - NULL for traditional auth';


--
-- Name: COLUMN users.user_provider_user_id; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.users.user_provider_user_id IS 'User ID from OAuth provider - NULL for traditional auth';


--
-- Name: COLUMN users.user_email_auth; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.users.user_email_auth IS 'Email from OAuth provider (may differ from primary email)';


--
-- Name: COLUMN users.is_email_verified; Type: COMMENT; Schema: public; Owner: postgres
--

COMMENT ON COLUMN public.users.is_email_verified IS 'Whether user has verified their email via OTP';


--
-- Name: users_auth; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.users_auth (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    email character varying(255) NOT NULL,
    name character varying(255),
    avatar_url text,
    provider character varying(50) NOT NULL,
    provider_user_id character varying(255) NOT NULL,
    raw_data jsonb,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    last_login_at timestamp with time zone
);


ALTER TABLE public.users_auth OWNER TO postgres;

--
-- Name: users_refresh_tokens; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.users_refresh_tokens (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id character varying(36) NOT NULL,
    token_hash character varying(255) NOT NULL,
    device_info character varying(255),
    ip_address inet,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    revoked_at timestamp with time zone,
    replaced_by_token_id uuid
);


ALTER TABLE public.users_refresh_tokens OWNER TO postgres;

--
-- Name: doctor_appointments appointment_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.doctor_appointments ALTER COLUMN appointment_id SET DEFAULT nextval('public.doctor_appointments_appointment_id_seq'::regclass);


--
-- Name: doctor_availability availability_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.doctor_availability ALTER COLUMN availability_id SET DEFAULT nextval('public.doctor_availability_availability_id_seq'::regclass);


--
-- Name: doctor_consultation_records record_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.doctor_consultation_records ALTER COLUMN record_id SET DEFAULT nextval('public.doctor_consultation_records_record_id_seq'::regclass);


--
-- Name: doctor_reviews review_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.doctor_reviews ALTER COLUMN review_id SET DEFAULT nextval('public.doctor_reviews_review_id_seq'::regclass);


--
-- Name: food_picture photo_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.food_picture ALTER COLUMN photo_id SET DEFAULT nextval('public.food_picture_photo_id_seq'::regclass);


--
-- Name: message_attachments attachment_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.message_attachments ALTER COLUMN attachment_id SET DEFAULT nextval('public.message_attachments_attachment_id_seq'::regclass);


--
-- Name: user_cart_items cart_items_cart_id_food_id_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_cart_items
    ADD CONSTRAINT cart_items_cart_id_food_id_key UNIQUE (cart_id, food_id);


--
-- Name: user_cart_items cart_items_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_cart_items
    ADD CONSTRAINT cart_items_pkey PRIMARY KEY (cart_item_id);


--
-- Name: foods foods_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.foods
    ADD CONSTRAINT foods_pkey PRIMARY KEY (food_id);


--
-- Name: activity idx_17115_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.activity
    ADD CONSTRAINT idx_17115_primary PRIMARY KEY (activity_id);


--
-- Name: activity_categories idx_17125_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.activity_categories
    ADD CONSTRAINT idx_17125_primary PRIMARY KEY (activity_categoryid);


--
-- Name: activity_recommendations idx_17132_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.activity_recommendations
    ADD CONSTRAINT idx_17132_primary PRIMARY KEY (recommendation_id);


--
-- Name: activity_recommendation_items idx_17138_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.activity_recommendation_items
    ADD CONSTRAINT idx_17138_primary PRIMARY KEY (item_id);


--
-- Name: chat_conversations idx_17145_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.chat_conversations
    ADD CONSTRAINT idx_17145_primary PRIMARY KEY (conversation_id);


--
-- Name: chat_messages idx_17154_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.chat_messages
    ADD CONSTRAINT idx_17154_primary PRIMARY KEY (message_id);


--
-- Name: doctor idx_17266_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.doctor
    ADD CONSTRAINT idx_17266_primary PRIMARY KEY (doctor_id);


--
-- Name: doctor_appointments idx_17289_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.doctor_appointments
    ADD CONSTRAINT idx_17289_primary PRIMARY KEY (appointment_id);


--
-- Name: doctor_availability idx_17304_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.doctor_availability
    ADD CONSTRAINT idx_17304_primary PRIMARY KEY (availability_id);


--
-- Name: doctor_consultation_records idx_17314_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.doctor_consultation_records
    ADD CONSTRAINT idx_17314_primary PRIMARY KEY (record_id);


--
-- Name: doctor_reviews idx_17325_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.doctor_reviews
    ADD CONSTRAINT idx_17325_primary PRIMARY KEY (review_id);


--
-- Name: food_category idx_17347_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.food_category
    ADD CONSTRAINT idx_17347_primary PRIMARY KEY (food_categoryid);


--
-- Name: food_picture idx_17353_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.food_picture
    ADD CONSTRAINT idx_17353_primary PRIMARY KEY (photo_id);


--
-- Name: food_recommendation idx_17361_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.food_recommendation
    ADD CONSTRAINT idx_17361_primary PRIMARY KEY (recommendation_id);


--
-- Name: message_attachments idx_17386_primary; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.message_attachments
    ADD CONSTRAINT idx_17386_primary PRIMARY KEY (attachment_id);


--
-- Name: logs_auth logs_auth_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.logs_auth
    ADD CONSTRAINT logs_auth_pkey PRIMARY KEY (log_id);


--
-- Name: otp_codes otp_codes_entity_id_entity_role_otp_purpose_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.otp_codes
    ADD CONSTRAINT otp_codes_entity_id_entity_role_otp_purpose_key UNIQUE (entity_id, entity_role, otp_purpose);


--
-- Name: otp_codes otp_codes_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.otp_codes
    ADD CONSTRAINT otp_codes_pkey PRIMARY KEY (otp_id);


--
-- Name: pending_registrations pending_registrations_email_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.pending_registrations
    ADD CONSTRAINT pending_registrations_email_key UNIQUE (email);


--
-- Name: pending_registrations pending_registrations_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.pending_registrations
    ADD CONSTRAINT pending_registrations_pkey PRIMARY KEY (pending_id);


--
-- Name: seller_profiles seller_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.seller_profiles
    ADD CONSTRAINT seller_pkey PRIMARY KEY (seller_id);


--
-- Name: users uq_user_oauth_provider; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT uq_user_oauth_provider UNIQUE (user_provider, user_provider_user_id);


--
-- Name: user_addresses user_addresses_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_addresses
    ADD CONSTRAINT user_addresses_pkey PRIMARY KEY (address_id);


--
-- Name: user_carts user_carts_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_carts
    ADD CONSTRAINT user_carts_pkey PRIMARY KEY (cart_id);


--
-- Name: user_carts user_carts_user_id_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_carts
    ADD CONSTRAINT user_carts_user_id_key UNIQUE (user_id);


--
-- Name: user_email_change_requests user_email_change_requests_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_email_change_requests
    ADD CONSTRAINT user_email_change_requests_pkey PRIMARY KEY (request_id);


--
-- Name: user_email_change_requests user_email_change_requests_verification_token_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_email_change_requests
    ADD CONSTRAINT user_email_change_requests_verification_token_key UNIQUE (verification_token);


--
-- Name: user_order_items user_order_items_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_order_items
    ADD CONSTRAINT user_order_items_pkey PRIMARY KEY (order_item_id);


--
-- Name: user_orders user_orders_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_orders
    ADD CONSTRAINT user_orders_pkey PRIMARY KEY (order_id);


--
-- Name: users_auth users_auth_email_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users_auth
    ADD CONSTRAINT users_auth_email_key UNIQUE (email);


--
-- Name: users_auth users_auth_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users_auth
    ADD CONSTRAINT users_auth_pkey PRIMARY KEY (id);


--
-- Name: users_auth users_auth_provider_provider_user_id_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users_auth
    ADD CONSTRAINT users_auth_provider_provider_user_id_key UNIQUE (provider, provider_user_id);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (user_id);


--
-- Name: users_refresh_tokens users_refresh_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users_refresh_tokens
    ADD CONSTRAINT users_refresh_tokens_pkey PRIMARY KEY (id);


--
-- Name: users_refresh_tokens users_refresh_tokens_token_hash_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users_refresh_tokens
    ADD CONSTRAINT users_refresh_tokens_token_hash_key UNIQUE (token_hash);


--
-- Name: users users_user_username_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_user_username_key UNIQUE (user_username);


--
-- Name: idx_17115_fk_activity_category; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_17115_fk_activity_category ON public.activity USING btree (activity_categoryid);


--
-- Name: idx_17132_user_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_17132_user_id ON public.activity_recommendations USING btree (user_id);


--
-- Name: idx_17138_activity_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_17138_activity_id ON public.activity_recommendation_items USING btree (activity_id);


--
-- Name: idx_17138_recommendation_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_17138_recommendation_id ON public.activity_recommendation_items USING btree (recommendation_id);


--
-- Name: idx_17154_conversation_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_17154_conversation_id ON public.chat_messages USING btree (conversation_id);


--
-- Name: idx_17289_doctor_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_17289_doctor_id ON public.doctor_appointments USING btree (doctor_id);


--
-- Name: idx_17289_user_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_17289_user_id ON public.doctor_appointments USING btree (user_id);


--
-- Name: idx_17304_doctor_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_17304_doctor_id ON public.doctor_availability USING btree (doctor_id);


--
-- Name: idx_17314_appointment_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX idx_17314_appointment_id ON public.doctor_consultation_records USING btree (appointment_id);


--
-- Name: idx_17325_doctor_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_17325_doctor_id ON public.doctor_reviews USING btree (doctor_id);


--
-- Name: idx_17325_user_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_17325_user_id ON public.doctor_reviews USING btree (user_id);


--
-- Name: idx_17353_food_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_17353_food_id ON public.food_picture USING btree (food_id);


--
-- Name: idx_17361_user_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_17361_user_id ON public.food_recommendation USING btree (user_id);


--
-- Name: idx_17386_message_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_17386_message_id ON public.message_attachments USING btree (message_id);


--
-- Name: idx_17414_idx_email; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX idx_17414_idx_email ON public.seller_profiles USING btree (seller_email);


--
-- Name: idx_17414_idx_username; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX idx_17414_idx_username ON public.seller_profiles USING btree (seller_username);


--
-- Name: idx_cart_items_cart_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_cart_items_cart_id ON public.user_cart_items USING btree (cart_id);


--
-- Name: idx_carts_user_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_carts_user_id ON public.user_carts USING btree (user_id);


--
-- Name: idx_email_change_token; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_email_change_token ON public.user_email_change_requests USING btree (verification_token);


--
-- Name: idx_foods_name; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_foods_name ON public.foods USING btree (food_name);


--
-- Name: idx_foods_seller_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_foods_seller_id ON public.foods USING btree (seller_id);


--
-- Name: idx_foods_tags; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_foods_tags ON public.foods USING gin (tags);


--
-- Name: idx_logs_auth_category; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_logs_auth_category ON public.logs_auth USING btree (log_category);


--
-- Name: idx_logs_auth_created_at; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_logs_auth_created_at ON public.logs_auth USING btree (created_at DESC);


--
-- Name: idx_logs_auth_level; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_logs_auth_level ON public.logs_auth USING btree (log_level);


--
-- Name: idx_logs_auth_user_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_logs_auth_user_id ON public.logs_auth USING btree (user_id);


--
-- Name: idx_order_items_order_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_order_items_order_id ON public.user_order_items USING btree (order_id);


--
-- Name: idx_orders_seller_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_orders_seller_id ON public.user_orders USING btree (seller_id);


--
-- Name: idx_orders_user_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_orders_user_id ON public.user_orders USING btree (user_id);


--
-- Name: idx_otp_codes_created_at; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_otp_codes_created_at ON public.otp_codes USING btree (entity_id, created_at DESC);


--
-- Name: idx_otp_codes_deletion_scheduled; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_otp_codes_deletion_scheduled ON public.otp_codes USING btree (deletion_scheduled_at) WHERE (deletion_scheduled_at IS NOT NULL);


--
-- Name: idx_otp_codes_expires_at; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_otp_codes_expires_at ON public.otp_codes USING btree (expires_at);


--
-- Name: idx_pending_reg_email; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_pending_reg_email ON public.pending_registrations USING btree (email);


--
-- Name: idx_pending_reg_expires; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_pending_reg_expires ON public.pending_registrations USING btree (expires_at);


--
-- Name: idx_pending_registrations_email; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_pending_registrations_email ON public.pending_registrations USING btree (email);


--
-- Name: idx_pending_registrations_expires_at; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_pending_registrations_expires_at ON public.pending_registrations USING btree (expires_at);


--
-- Name: idx_pending_registrations_username; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_pending_registrations_username ON public.pending_registrations USING btree (username);


--
-- Name: idx_refresh_tokens_expires_at; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_refresh_tokens_expires_at ON public.users_refresh_tokens USING btree (expires_at);


--
-- Name: idx_refresh_tokens_token_hash; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_refresh_tokens_token_hash ON public.users_refresh_tokens USING btree (token_hash);


--
-- Name: idx_refresh_tokens_user_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_refresh_tokens_user_id ON public.users_refresh_tokens USING btree (user_id);


--
-- Name: idx_user_addresses_active; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_user_addresses_active ON public.user_addresses USING btree (user_id, is_active) WHERE (is_active = true);


--
-- Name: idx_user_addresses_default; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_user_addresses_default ON public.user_addresses USING btree (user_id, is_default) WHERE (is_default = true);


--
-- Name: idx_user_addresses_one_default; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX idx_user_addresses_one_default ON public.user_addresses USING btree (user_id) WHERE (is_default = true);


--
-- Name: idx_user_addresses_user_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_user_addresses_user_id ON public.user_addresses USING btree (user_id);


--
-- Name: idx_users_email; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_users_email ON public.users_auth USING btree (email);


--
-- Name: idx_users_email_auth; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_users_email_auth ON public.users USING btree (user_email_auth);


--
-- Name: idx_users_provider; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_users_provider ON public.users USING btree (user_provider, user_provider_user_id);


--
-- Name: idx_users_provider_user_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_users_provider_user_id ON public.users_auth USING btree (provider, provider_user_id);


--
-- Name: idx_users_unverified; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_users_unverified ON public.users USING btree (is_email_verified, user_created_at_auth) WHERE (is_email_verified = false);


--
-- Name: idx_users_username; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_users_username ON public.users USING btree (user_username);


--
-- Name: user_addresses Trigger_Ensure_One_Default_Address; Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER "Trigger_Ensure_One_Default_Address" BEFORE INSERT OR UPDATE ON public.user_addresses FOR EACH ROW EXECUTE FUNCTION public.ensure_one_default_address();


--
-- Name: chat_conversations on_update_current_timestamp; Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER on_update_current_timestamp BEFORE UPDATE ON public.chat_conversations FOR EACH ROW EXECUTE FUNCTION public.on_update_current_timestamp_chat_conversations();


--
-- Name: doctor_appointments on_update_current_timestamp; Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER on_update_current_timestamp BEFORE UPDATE ON public.doctor_appointments FOR EACH ROW EXECUTE FUNCTION public.on_update_current_timestamp_doctor_appointments();


--
-- Name: doctor_consultation_records on_update_current_timestamp; Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER on_update_current_timestamp BEFORE UPDATE ON public.doctor_consultation_records FOR EACH ROW EXECUTE FUNCTION public.on_update_current_timestamp_doctor_consultation_records();


--
-- Name: user_addresses trigger_user_addresses_updated_at; Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER trigger_user_addresses_updated_at BEFORE UPDATE ON public.user_addresses FOR EACH ROW EXECUTE FUNCTION public.update_user_addresses_updated_at();


--
-- Name: users update_users_updated_at; Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON public.users FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: users_auth update_users_updated_at; Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON public.users_auth FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: activity_recommendation_items activity_recommendation_items_ibfk_1; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.activity_recommendation_items
    ADD CONSTRAINT activity_recommendation_items_ibfk_1 FOREIGN KEY (recommendation_id) REFERENCES public.activity_recommendations(recommendation_id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: activity_recommendation_items activity_recommendation_items_ibfk_2; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.activity_recommendation_items
    ADD CONSTRAINT activity_recommendation_items_ibfk_2 FOREIGN KEY (activity_id) REFERENCES public.activity(activity_id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: user_cart_items cart_items_cart_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_cart_items
    ADD CONSTRAINT cart_items_cart_id_fkey FOREIGN KEY (cart_id) REFERENCES public.user_carts(cart_id) ON DELETE CASCADE;


--
-- Name: user_cart_items cart_items_food_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_cart_items
    ADD CONSTRAINT cart_items_food_id_fkey FOREIGN KEY (food_id) REFERENCES public.foods(food_id) ON DELETE CASCADE;


--
-- Name: chat_messages chat_messages_ibfk_1; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.chat_messages
    ADD CONSTRAINT chat_messages_ibfk_1 FOREIGN KEY (conversation_id) REFERENCES public.chat_conversations(conversation_id) ON UPDATE RESTRICT ON DELETE CASCADE;


--
-- Name: doctor_appointments doctor_appointments_ibfk_2; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.doctor_appointments
    ADD CONSTRAINT doctor_appointments_ibfk_2 FOREIGN KEY (doctor_id) REFERENCES public.doctor(doctor_id) ON UPDATE RESTRICT ON DELETE CASCADE;


--
-- Name: doctor_availability doctor_availability_ibfk_1; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.doctor_availability
    ADD CONSTRAINT doctor_availability_ibfk_1 FOREIGN KEY (doctor_id) REFERENCES public.doctor(doctor_id) ON UPDATE RESTRICT ON DELETE CASCADE;


--
-- Name: doctor_consultation_records doctor_consultation_records_ibfk_1; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.doctor_consultation_records
    ADD CONSTRAINT doctor_consultation_records_ibfk_1 FOREIGN KEY (appointment_id) REFERENCES public.doctor_appointments(appointment_id) ON UPDATE RESTRICT ON DELETE CASCADE;


--
-- Name: doctor_reviews doctor_reviews_ibfk_1; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.doctor_reviews
    ADD CONSTRAINT doctor_reviews_ibfk_1 FOREIGN KEY (doctor_id) REFERENCES public.doctor(doctor_id) ON UPDATE RESTRICT ON DELETE CASCADE;


--
-- Name: activity fk_activity_category; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.activity
    ADD CONSTRAINT fk_activity_category FOREIGN KEY (activity_categoryid) REFERENCES public.activity_categories(activity_categoryid) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: foods foods_seller_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.foods
    ADD CONSTRAINT foods_seller_id_fkey FOREIGN KEY (seller_id) REFERENCES public.seller_profiles(seller_id);


--
-- Name: message_attachments message_attachments_ibfk_1; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.message_attachments
    ADD CONSTRAINT message_attachments_ibfk_1 FOREIGN KEY (message_id) REFERENCES public.chat_messages(message_id) ON UPDATE RESTRICT ON DELETE CASCADE;


--
-- Name: user_addresses user_addresses_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_addresses
    ADD CONSTRAINT user_addresses_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id) ON DELETE CASCADE;


--
-- Name: user_carts user_carts_seller_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_carts
    ADD CONSTRAINT user_carts_seller_id_fkey FOREIGN KEY (seller_id) REFERENCES public.seller_profiles(seller_id) ON DELETE SET NULL;


--
-- Name: user_carts user_carts_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_carts
    ADD CONSTRAINT user_carts_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id) ON DELETE CASCADE;


--
-- Name: user_email_change_requests user_email_change_requests_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_email_change_requests
    ADD CONSTRAINT user_email_change_requests_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id) ON DELETE CASCADE;


--
-- Name: user_order_items user_order_items_food_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_order_items
    ADD CONSTRAINT user_order_items_food_id_fkey FOREIGN KEY (food_id) REFERENCES public.foods(food_id);


--
-- Name: user_order_items user_order_items_order_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_order_items
    ADD CONSTRAINT user_order_items_order_id_fkey FOREIGN KEY (order_id) REFERENCES public.user_orders(order_id) ON DELETE CASCADE;


--
-- Name: user_orders user_orders_seller_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_orders
    ADD CONSTRAINT user_orders_seller_id_fkey FOREIGN KEY (seller_id) REFERENCES public.seller_profiles(seller_id);


--
-- Name: user_orders user_orders_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_orders
    ADD CONSTRAINT user_orders_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id);


--
-- Name: users_refresh_tokens users_refresh_tokens_replaced_by_token_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users_refresh_tokens
    ADD CONSTRAINT users_refresh_tokens_replaced_by_token_id_fkey FOREIGN KEY (replaced_by_token_id) REFERENCES public.users_refresh_tokens(id);


--
-- Name: users_refresh_tokens users_refresh_tokens_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users_refresh_tokens
    ADD CONSTRAINT users_refresh_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--
