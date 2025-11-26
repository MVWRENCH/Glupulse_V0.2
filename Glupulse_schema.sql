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
-- Name: btree_gist; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS btree_gist WITH SCHEMA public;


--
-- Name: EXTENSION btree_gist; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION btree_gist IS 'support for indexing common datatypes in GiST';


--
-- Name: pg_trgm; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA public;


--
-- Name: EXTENSION pg_trgm; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION pg_trgm IS 'text similarity measurement and index searching based on trigrams';


--
-- Name: uuid-ossp; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA public;


--
-- Name: EXTENSION "uuid-ossp"; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION "uuid-ossp" IS 'generate universally unique identifiers (UUIDs)';


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
    'suspended',
    'pending'
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
-- Name: calculate_glucose_trend(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.calculate_glucose_trend() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    last_glucose_val INTEGER;
    last_reading_time TIMESTAMPTZ;
    time_diff_minutes INTEGER;
    glucose_change INTEGER;
    rate_per_minute INTEGER;
    rate_per_five_minutes INTEGER;
BEGIN
    -- 1. Find the previous reading (by reading_timestamp)
    SELECT glucose_value, reading_timestamp
    INTO last_glucose_val, last_reading_time
    FROM user_glucose_readings
    WHERE user_id = NEW.user_id
    AND reading_timestamp < NEW.reading_timestamp -- Must be strictly older than the NEW record
    ORDER BY reading_timestamp DESC
    LIMIT 1;

    -- If a previous record was found
    IF last_glucose_val IS NOT NULL THEN
        -- 2. Calculate time difference in minutes
        time_diff_minutes := EXTRACT(EPOCH FROM (NEW.reading_timestamp - last_reading_time)) / 60;
        
        -- Prevent division by zero and handle identical timestamps
        IF time_diff_minutes <= 0 THEN
            NEW.trend_arrow := 'stable';
            NEW.rate_of_change := 0;
            RETURN NEW;
        END IF;
        
        -- 3. Calculate glucose change and rate of change (mg/dL per minute)
        glucose_change := NEW.glucose_value - last_glucose_val;
        
        -- Calculate rate per minute (INTEGER division is fine here for the approximation)
        rate_per_minute := ROUND(glucose_change::NUMERIC / time_diff_minutes::NUMERIC);
        
        -- 4. Determine trend arrow (based on rate per 5 minutes)
        rate_per_five_minutes := rate_per_minute * 5;

        -- Store the rate of change
        NEW.rate_of_change := rate_per_minute;

        -- Determine the trend (CGM Standard Thresholds)
        -- NOTE: We check the extremes first and ensure the stable range is tight.
        IF rate_per_five_minutes >= 6 THEN
            NEW.trend_arrow := 'rising_rapidly'; -- >= 6 mg/dL per 5 min (> 72 mg/dL per hour)
        ELSIF rate_per_five_minutes <= -6 THEN
            NEW.trend_arrow := 'falling_rapidly'; -- <= -6 mg/dL per 5 min (< -72 mg/dL per hour)
        ELSIF rate_per_five_minutes >= 3 THEN
            NEW.trend_arrow := 'rising'; -- 3 to 6 mg/dL per 5 min
        ELSIF rate_per_five_minutes <= -3 THEN
            NEW.trend_arrow := 'falling'; -- -3 to -6 mg/dL per 5 min
        ELSE
            NEW.trend_arrow := 'stable'; -- -2 to +2 mg/dL per 5 min (This covers your -10 case which is incorrect for falling_rapidly)
        END IF;

    ELSE
        -- This is the first record.
        NEW.trend_arrow := 'unknown';
        NEW.rate_of_change := 0;
    END IF;

    RETURN NEW;
END;
$$;


ALTER FUNCTION public.calculate_glucose_trend() OWNER TO postgres;

--
-- Name: calculate_hba1c_trend(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.calculate_hba1c_trend() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    last_hba1c_val NUMERIC(4,2);
    hba1c_change NUMERIC(5,2);
BEGIN
    -- 1. Find the previous HBA1C value for this user.
    -- CRITICAL: It must be for a test date strictly BEFORE the current one.
    SELECT hba1c_percentage
    INTO last_hba1c_val
    FROM user_hba1c_records
    WHERE user_id = NEW.user_id
    AND test_date < NEW.test_date -- Use the date from the NEW record
    ORDER BY test_date DESC, created_at DESC
    LIMIT 1;

    -- If a previous record was found (last_hba1c_val is not NULL)
    IF last_hba1c_val IS NOT NULL THEN
        -- Calculate Change: Previous value minus New value.
        -- Positive change means improvement (Lower HBA1C).
        hba1c_change := last_hba1c_val - NEW.hba1c_percentage;
        
        -- Apply the calculated change to the NEW record
        NEW.change_from_previous := hba1c_change;

        -- Calculate Trend (Tolerance: 0.1% for stability)
        IF ABS(hba1c_change) < 0.1 THEN
            NEW.trend := 'stable';
        ELSIF hba1c_change > 0 THEN
            NEW.trend := 'improving'; -- e.g., 7.0 (old) - 6.8 (new) = +0.2
        ELSE
            NEW.trend := 'worsening'; -- e.g., 7.0 (old) - 7.2 (new) = -0.2
        END IF;

    ELSE
        -- This is the first record. Set change to 0 and trend to stable.
        NEW.change_from_previous := 0.00;
        NEW.trend := 'stable';
    END IF;

    -- 2. Calculate HBA1C mmol/mol (IFCC)
    -- Formula: mmol/mol = (10.93 * HBA1C %) - 23.5
    -- We must ensure the result is rounded and cast to INTEGER/NUMERIC appropriately.
    NEW.hba1c_mmol_mol := ROUND((10.93 * NEW.hba1c_percentage) - 23.5);

    RETURN NEW;
END;
$$;


ALTER FUNCTION public.calculate_hba1c_trend() OWNER TO postgres;

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
-- Name: update_seller_profiles_updated_at(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.update_seller_profiles_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;


ALTER FUNCTION public.update_seller_profiles_updated_at() OWNER TO postgres;

--
-- Name: update_updated_at_column(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.update_updated_at_column() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = NOW();
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
-- Name: update_user_profile_with_latest_hba1c(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.update_user_profile_with_latest_hba1c() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    latest_record RECORD;
BEGIN
    -- 1. Find the ABSOLUTE latest HBA1C record for the user 
    -- (This handles cases where a user updates an old record or inserts a new one).
    SELECT 
        hba1c_percentage,
        test_date -- Assuming this column is named 'last_hba1c_date' in your records table, although 'test_date' is likely correct.
    INTO latest_record
    FROM user_hba1c_records
    WHERE user_id = NEW.user_id
    ORDER BY test_date DESC, created_at DESC
    LIMIT 1;

    -- 2. Update the main user_health_profiles table with the latest summary data.
    UPDATE user_health_profiles
    SET 
        last_hba1c = latest_record.hba1c_percentage,
        last_hba1c_date = latest_record.test_date,
        updated_at = NOW() -- Update the profile timestamp
    WHERE user_id = NEW.user_id;

    RETURN NEW;
END;
$$;


ALTER FUNCTION public.update_user_profile_with_latest_hba1c() OWNER TO postgres;

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
-- Name: activities; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.activities (
    id integer NOT NULL,
    activity_code character varying(50),
    activity_name character varying(100) NOT NULL,
    description text,
    image_url text,
    met_value numeric(4,1) DEFAULT 1.0 NOT NULL,
    measurement_unit character varying(20),
    recommended_min_value numeric(10,2) DEFAULT 30,
    CONSTRAINT activities_measurement_unit_check CHECK (((measurement_unit)::text = ANY ((ARRAY['TIME'::character varying, 'DISTANCE'::character varying, 'REPS'::character varying, 'STEPS'::character varying])::text[])))
);


ALTER TABLE public.activities OWNER TO postgres;

--
-- Name: activities_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.activities_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.activities_id_seq OWNER TO postgres;

--
-- Name: activities_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.activities_id_seq OWNED BY public.activities.id;


--
-- Name: activity_types; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.activity_types (
    activity_type_id integer NOT NULL,
    activity_code character varying(50) NOT NULL,
    display_name character varying(100) NOT NULL,
    intensity_level character varying(20) DEFAULT 'moderate'::character varying
);


ALTER TABLE public.activity_types OWNER TO postgres;

--
-- Name: activity_types_activity_type_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.activity_types_activity_type_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.activity_types_activity_type_id_seq OWNER TO postgres;

--
-- Name: activity_types_activity_type_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.activity_types_activity_type_id_seq OWNED BY public.activity_types.activity_type_id;


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
-- Name: food_categories; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.food_categories (
    category_id integer NOT NULL,
    category_code character varying(50) NOT NULL,
    display_name character varying(100) NOT NULL,
    description text
);


ALTER TABLE public.food_categories OWNER TO postgres;

--
-- Name: food_categories_category_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.food_categories_category_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.food_categories_category_id_seq OWNER TO postgres;

--
-- Name: food_categories_category_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.food_categories_category_id_seq OWNED BY public.food_categories.category_id;


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
-- Name: health_condition_types; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.health_condition_types (
    condition_id integer NOT NULL,
    condition_code character varying(50) NOT NULL,
    display_name character varying(100) NOT NULL,
    description text
);


ALTER TABLE public.health_condition_types OWNER TO postgres;

--
-- Name: health_condition_types_condition_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.health_condition_types_condition_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.health_condition_types_condition_id_seq OWNER TO postgres;

--
-- Name: health_condition_types_condition_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.health_condition_types_condition_id_seq OWNED BY public.health_condition_types.condition_id;


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
-- Name: meal_types; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.meal_types (
    meal_type_id integer NOT NULL,
    meal_code character varying(50) NOT NULL,
    display_name character varying(100) NOT NULL
);


ALTER TABLE public.meal_types OWNER TO postgres;

--
-- Name: meal_types_meal_type_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.meal_types_meal_type_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.meal_types_meal_type_id_seq OWNER TO postgres;

--
-- Name: meal_types_meal_type_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.meal_types_meal_type_id_seq OWNED BY public.meal_types.meal_type_id;


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
-- Name: recommendation_types; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.recommendation_types (
    rec_type_id integer NOT NULL,
    rec_code character varying(50) NOT NULL,
    display_name character varying(100) NOT NULL
);


ALTER TABLE public.recommendation_types OWNER TO postgres;

--
-- Name: recommendation_types_rec_type_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.recommendation_types_rec_type_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.recommendation_types_rec_type_id_seq OWNER TO postgres;

--
-- Name: recommendation_types_rec_type_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.recommendation_types_rec_type_id_seq OWNED BY public.recommendation_types.rec_type_id;


--
-- Name: roles; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.roles (
    role_id integer NOT NULL,
    role_name character varying(50) NOT NULL
);


ALTER TABLE public.roles OWNER TO postgres;

--
-- Name: roles_role_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.roles_role_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.roles_role_id_seq OWNER TO postgres;

--
-- Name: roles_role_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.roles_role_id_seq OWNED BY public.roles.role_id;


--
-- Name: seller_profiles; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.seller_profiles (
    seller_id uuid CONSTRAINT seller_seller_id_not_null NOT NULL,
    user_id character varying(100) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    store_name character varying(100) NOT NULL,
    store_description text,
    store_phone_number character varying(30),
    is_open_manually boolean DEFAULT true NOT NULL,
    business_hours jsonb,
    verification_status character varying(20) DEFAULT 'pending'::character varying NOT NULL,
    logo_url text,
    banner_url text,
    address_line1 text,
    address_line2 text,
    district text,
    city text,
    province text,
    postal_code character varying(10),
    latitude numeric(10,7),
    longitude numeric(10,7),
    gmaps_link text
);


ALTER TABLE public.seller_profiles OWNER TO postgres;

--
-- Name: user_activity_logs; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.user_activity_logs (
    activity_id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    user_id text NOT NULL,
    activity_timestamp timestamp with time zone NOT NULL,
    activity_code character varying(50) NOT NULL,
    intensity character varying(20) NOT NULL,
    perceived_exertion integer,
    duration_minutes integer NOT NULL,
    steps_count integer,
    pre_activity_carbs integer,
    water_intake_ml integer,
    issue_description text,
    source character varying(30) NOT NULL,
    sync_id character varying(200),
    notes text,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT user_activity_logs_duration_minutes_check CHECK ((duration_minutes > 0)),
    CONSTRAINT user_activity_logs_intensity_check CHECK (((intensity)::text = ANY ((ARRAY['low'::character varying, 'moderate'::character varying, 'high'::character varying])::text[]))),
    CONSTRAINT user_activity_logs_perceived_exertion_check CHECK (((perceived_exertion >= 1) AND (perceived_exertion <= 10))),
    CONSTRAINT user_activity_logs_source_check CHECK (((source)::text = ANY ((ARRAY['manual'::character varying, 'fitness_tracker'::character varying, 'cgm_integrated'::character varying])::text[])))
);


ALTER TABLE public.user_activity_logs OWNER TO postgres;

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
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    address_district text
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
-- Name: user_food_insights; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.user_food_insights (
    insight_id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    user_id text NOT NULL,
    food_id uuid,
    food_name character varying(200) NOT NULL,
    times_consumed integer DEFAULT 0,
    last_eaten_at timestamp with time zone,
    health_score integer,
    avg_glucose_spike integer,
    avg_time_to_peak_minutes integer,
    ai_tags jsonb DEFAULT '{}'::jsonb,
    is_trigger_food boolean DEFAULT false,
    is_favorite boolean DEFAULT false,
    user_notes text,
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT user_food_insights_health_score_check CHECK (((health_score >= 0) AND (health_score <= 100)))
);


ALTER TABLE public.user_food_insights OWNER TO postgres;

--
-- Name: user_glucose_readings; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.user_glucose_readings (
    reading_id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    user_id text NOT NULL,
    glucose_value integer NOT NULL,
    reading_timestamp timestamp with time zone DEFAULT now(),
    reading_type character varying(30) NOT NULL,
    trend_arrow character varying(20),
    rate_of_change integer,
    source character varying(30) DEFAULT 'manual'::character varying,
    device_id character varying(100),
    device_name character varying(100),
    is_flagged boolean DEFAULT false,
    flag_reason text,
    is_outlier boolean DEFAULT false,
    notes text,
    symptoms text[],
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT user_glucose_readings_glucose_value_check CHECK (((glucose_value >= 20) AND (glucose_value <= 600))),
    CONSTRAINT user_glucose_readings_reading_type_check CHECK (((reading_type)::text = ANY ((ARRAY['fasting'::character varying, 'pre_meal'::character varying, 'post_meal_1h'::character varying, 'post_meal_2h'::character varying, 'bedtime'::character varying, 'overnight'::character varying, 'random'::character varying, 'exercise'::character varying, 'sick_day'::character varying])::text[]))),
    CONSTRAINT user_glucose_readings_source_check CHECK (((source)::text = ANY ((ARRAY['manual'::character varying, 'cgm'::character varying, 'glucose_meter'::character varying, 'lab_test'::character varying])::text[]))),
    CONSTRAINT user_glucose_readings_trend_arrow_check CHECK (((trend_arrow)::text = ANY ((ARRAY['rising_rapidly'::character varying, 'rising'::character varying, 'stable'::character varying, 'falling'::character varying, 'falling_rapidly'::character varying, 'unknown'::character varying])::text[])))
);


ALTER TABLE public.user_glucose_readings OWNER TO postgres;

--
-- Name: user_hba1c_records; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.user_hba1c_records (
    hba1c_id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    user_id text NOT NULL,
    test_date date NOT NULL,
    hba1c_percentage numeric(4,2) NOT NULL,
    hba1c_mmol_mol integer,
    estimated_avg_glucose integer,
    treatment_changed boolean DEFAULT false,
    medication_changes text,
    diet_changes text,
    activity_changes text,
    change_from_previous numeric(4,2),
    trend character varying(20),
    notes text,
    document_url text,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT user_hba1c_records_hba1c_percentage_check CHECK (((hba1c_percentage >= 4.0) AND (hba1c_percentage <= 20.0))),
    CONSTRAINT user_hba1c_records_trend_check CHECK (((trend)::text = ANY ((ARRAY['improving'::character varying, 'stable'::character varying, 'worsening'::character varying])::text[])))
);


ALTER TABLE public.user_hba1c_records OWNER TO postgres;

--
-- Name: user_health_events; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.user_health_events (
    event_id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    user_id text NOT NULL,
    event_date date NOT NULL,
    event_type character varying(50) NOT NULL,
    severity character varying(20),
    glucose_value integer,
    ketone_value_mmol numeric(4,2),
    symptoms text[],
    treatments text[],
    required_medical_attention boolean DEFAULT false,
    notes text,
    created_at timestamp with time zone DEFAULT now(),
    updated_at character varying DEFAULT now(),
    CONSTRAINT user_health_events_event_type_check CHECK (((event_type)::text = ANY ((ARRAY['hypoglycemia'::character varying, 'hyperglycemia'::character varying, 'illness'::character varying, 'other'::character varying])::text[]))),
    CONSTRAINT user_health_events_severity_check CHECK (((severity)::text = ANY ((ARRAY['mild'::character varying, 'moderate'::character varying, 'severe'::character varying, 'critical'::character varying])::text[])))
);


ALTER TABLE public.user_health_events OWNER TO postgres;

--
-- Name: user_health_profiles; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.user_health_profiles (
    profile_id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    user_id text NOT NULL,
    app_experience character varying(20) DEFAULT 'simple'::character varying NOT NULL,
    condition_id integer NOT NULL,
    diagnosis_date date,
    years_with_condition numeric(5,2),
    treatment_types character varying(50)[],
    target_glucose_fasting integer,
    target_glucose_postprandial integer,
    uses_cgm boolean DEFAULT false,
    cgm_device character varying(50),
    cgm_api_connected boolean DEFAULT false,
    height_cm numeric(5,2) NOT NULL,
    current_weight_kg numeric(5,2) NOT NULL,
    target_weight_kg numeric(5,2),
    bmi numeric(4,2) GENERATED ALWAYS AS ((current_weight_kg / NULLIF(((height_cm / (100)::numeric) * (height_cm / (100)::numeric)), (0)::numeric))) STORED,
    waist_circumference_cm numeric(5,2),
    body_fat_percentage numeric(4,2),
    hba1c_target numeric(4,2),
    last_hba1c numeric(4,2),
    last_hba1c_date date,
    activity_level character varying(30) DEFAULT 'lightly_active'::character varying,
    daily_steps_goal integer,
    weekly_exercise_goal_minutes integer,
    preferred_activity_type_ids integer[],
    dietary_pattern character varying(50),
    daily_carb_target_grams integer,
    daily_calorie_target integer,
    daily_protein_target_grams integer,
    daily_fat_target_grams integer,
    meals_per_day integer,
    snacks_per_day integer,
    food_allergies character varying(100)[],
    food_intolerances character varying(100)[],
    foods_to_avoid character varying(100)[],
    cultural_cuisines character varying(50)[],
    dietary_restrictions character varying(50)[],
    has_hypertension boolean DEFAULT false,
    hypertension_medication text,
    has_kidney_disease boolean DEFAULT false,
    kidney_disease_stage integer,
    egfr_value numeric(5,2),
    has_cardiovascular_disease boolean DEFAULT false,
    has_neuropathy boolean DEFAULT false,
    has_retinopathy boolean DEFAULT false,
    has_gastroparesis boolean DEFAULT false,
    has_hypoglycemia_unawareness boolean DEFAULT false,
    other_conditions text[],
    smoking_status character varying(20),
    smoking_years integer,
    alcohol_frequency character varying(30),
    alcohol_drinks_per_week integer,
    stress_level character varying(20),
    typical_sleep_hours numeric(3,1),
    sleep_quality character varying(20),
    is_pregnant boolean DEFAULT false,
    is_breastfeeding boolean DEFAULT false,
    expected_due_date date,
    preferred_units character varying(20) DEFAULT 'metric'::character varying,
    glucose_unit character varying(20) DEFAULT 'mg_dl'::character varying,
    timezone character varying(50) DEFAULT 'UTC'::character varying,
    language_code character varying(10) DEFAULT 'en'::character varying,
    enable_glucose_alerts boolean DEFAULT true,
    enable_meal_reminders boolean DEFAULT true,
    enable_activity_reminders boolean DEFAULT true,
    enable_medication_reminders boolean DEFAULT true,
    share_data_for_research boolean DEFAULT false,
    share_anonymized_data boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT user_health_profiles_activity_level_check CHECK (((activity_level)::text = ANY ((ARRAY['sedentary'::character varying, 'lightly_active'::character varying, 'moderately_active'::character varying, 'very_active'::character varying, 'extremely_active'::character varying])::text[]))),
    CONSTRAINT user_health_profiles_alcohol_frequency_check CHECK (((alcohol_frequency)::text = ANY ((ARRAY['never'::character varying, 'rarely'::character varying, 'weekly'::character varying, 'daily'::character varying])::text[]))),
    CONSTRAINT user_health_profiles_app_experience_check CHECK (((app_experience)::text = ANY ((ARRAY['simple'::character varying, 'advanced'::character varying])::text[]))),
    CONSTRAINT user_health_profiles_glucose_unit_check CHECK (((glucose_unit)::text = ANY ((ARRAY['mg_dl'::character varying, 'mmol_l'::character varying])::text[]))),
    CONSTRAINT user_health_profiles_kidney_disease_stage_check CHECK (((kidney_disease_stage >= 1) AND (kidney_disease_stage <= 5))),
    CONSTRAINT user_health_profiles_preferred_units_check CHECK (((preferred_units)::text = ANY ((ARRAY['metric'::character varying, 'imperial'::character varying])::text[]))),
    CONSTRAINT user_health_profiles_sleep_quality_check CHECK (((sleep_quality)::text = ANY ((ARRAY['poor'::character varying, 'fair'::character varying, 'good'::character varying, 'excellent'::character varying])::text[]))),
    CONSTRAINT user_health_profiles_smoking_status_check CHECK (((smoking_status)::text = ANY ((ARRAY['never'::character varying, 'former'::character varying, 'current'::character varying])::text[]))),
    CONSTRAINT user_health_profiles_stress_level_check CHECK (((stress_level)::text = ANY ((ARRAY['low'::character varying, 'moderate'::character varying, 'high'::character varying, 'very_high'::character varying])::text[]))),
    CONSTRAINT valid_bmi CHECK (((bmi IS NULL) OR ((bmi >= (10)::numeric) AND (bmi <= (100)::numeric)))),
    CONSTRAINT valid_hba1c CHECK (((hba1c_target >= 4.0) AND (hba1c_target <= 10.0))),
    CONSTRAINT valid_height CHECK (((height_cm >= (100)::numeric) AND (height_cm <= (250)::numeric))),
    CONSTRAINT valid_last_hba1c CHECK (((last_hba1c IS NULL) OR ((last_hba1c >= 4.0) AND (last_hba1c <= 20.0)))),
    CONSTRAINT valid_weight CHECK (((current_weight_kg >= (20)::numeric) AND (current_weight_kg <= (300)::numeric)))
);


ALTER TABLE public.user_health_profiles OWNER TO postgres;

--
-- Name: user_meal_items; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.user_meal_items (
    item_id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    meal_id uuid NOT NULL,
    food_name character varying(200) NOT NULL,
    food_id uuid,
    seller character varying(100),
    serving_size character varying(100),
    serving_size_grams numeric(8,2),
    quantity numeric(6,2) DEFAULT 1,
    calories integer,
    carbs_grams numeric(6,2) NOT NULL,
    fiber_grams numeric(5,2),
    protein_grams numeric(6,2),
    fat_grams numeric(6,2),
    sugar_grams numeric(6,2),
    sodium_mg integer,
    glycemic_index integer,
    glycemic_load numeric(5,2),
    food_category character varying(50),
    created_at timestamp with time zone DEFAULT now(),
    CONSTRAINT user_meal_items_glycemic_index_check CHECK (((glycemic_index >= 0) AND (glycemic_index <= 100)))
);


ALTER TABLE public.user_meal_items OWNER TO postgres;

--
-- Name: user_meal_logs; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.user_meal_logs (
    meal_id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    user_id text NOT NULL,
    meal_timestamp timestamp with time zone DEFAULT now() NOT NULL,
    meal_type_id integer NOT NULL,
    description text,
    total_calories integer,
    total_carbs_grams numeric(6,2),
    total_protein_grams numeric(6,2),
    total_fat_grams numeric(6,2),
    total_fiber_grams numeric(6,2),
    total_sugar_grams numeric(6,2),
    tags text[],
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


ALTER TABLE public.user_meal_logs OWNER TO postgres;

--
-- Name: user_medication_logs; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.user_medication_logs (
    medicationlog_id uuid DEFAULT public.uuid_generate_v4() CONSTRAINT user_medication_logs_log_id_not_null NOT NULL,
    user_id text NOT NULL,
    medication_id integer,
    medication_name character varying(100) NOT NULL,
    "timestamp" timestamp with time zone DEFAULT now() NOT NULL,
    dose_amount numeric(8,2) NOT NULL,
    reason character varying(50),
    is_pump_delivery boolean DEFAULT false,
    delivery_duration_minutes integer DEFAULT 0,
    notes text,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT user_medication_logs_reason_check CHECK (((reason)::text = ANY ((ARRAY['meal_bolus'::character varying, 'correction'::character varying, 'basal'::character varying, 'medication_schedule'::character varying])::text[])))
);


ALTER TABLE public.user_medication_logs OWNER TO postgres;

--
-- Name: user_medications; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.user_medications (
    medication_id integer NOT NULL,
    user_id text,
    display_name character varying(100) NOT NULL,
    medication_type character varying(50) NOT NULL,
    default_dose_unit character varying(20) DEFAULT 'units'::character varying,
    is_active boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT user_medications_medication_type_check CHECK (((medication_type)::text = ANY (ARRAY[('INSULIN'::character varying)::text, ('BIGUANIDE'::character varying)::text, ('GLP1'::character varying)::text, ('SGLT2'::character varying)::text, ('DPP4'::character varying)::text, ('OTC'::character varying)::text, ('SUPPLEMENT'::character varying)::text, ('OTHER_RX'::character varying)::text])))
);


ALTER TABLE public.user_medications OWNER TO postgres;

--
-- Name: user_medications_medication_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.user_medications_medication_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.user_medications_medication_id_seq OWNER TO postgres;

--
-- Name: user_medications_medication_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.user_medications_medication_id_seq OWNED BY public.user_medications.medication_id;


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
-- Name: user_roles; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.user_roles (
    user_id text NOT NULL,
    role_id integer NOT NULL
);


ALTER TABLE public.user_roles OWNER TO postgres;

--
-- Name: user_sleep_logs; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.user_sleep_logs (
    sleep_id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    user_id text NOT NULL,
    sleep_date date NOT NULL,
    bed_time timestamp with time zone NOT NULL,
    wake_time timestamp with time zone NOT NULL,
    quality_rating integer,
    tracker_score integer,
    deep_sleep_minutes integer,
    rem_sleep_minutes integer,
    light_sleep_minutes integer,
    awake_minutes integer,
    average_hrv integer,
    resting_heart_rate integer,
    tags text[],
    source character varying(30) DEFAULT 'manual'::character varying,
    notes text,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT user_sleep_logs_quality_rating_check CHECK (((quality_rating >= 1) AND (quality_rating <= 5))),
    CONSTRAINT user_sleep_logs_source_check CHECK (((source)::text = ANY ((ARRAY['manual'::character varying, 'wearable_sync'::character varying])::text[]))),
    CONSTRAINT user_sleep_logs_tracker_score_check CHECK (((tracker_score >= 0) AND (tracker_score <= 100)))
);


ALTER TABLE public.user_sleep_logs OWNER TO postgres;

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
    created_at timestamp with time zone,
    updated_at timestamp with time zone,
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
-- Name: activities id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.activities ALTER COLUMN id SET DEFAULT nextval('public.activities_id_seq'::regclass);


--
-- Name: activity_types activity_type_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.activity_types ALTER COLUMN activity_type_id SET DEFAULT nextval('public.activity_types_activity_type_id_seq'::regclass);


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
-- Name: food_categories category_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.food_categories ALTER COLUMN category_id SET DEFAULT nextval('public.food_categories_category_id_seq'::regclass);


--
-- Name: food_picture photo_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.food_picture ALTER COLUMN photo_id SET DEFAULT nextval('public.food_picture_photo_id_seq'::regclass);


--
-- Name: health_condition_types condition_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.health_condition_types ALTER COLUMN condition_id SET DEFAULT nextval('public.health_condition_types_condition_id_seq'::regclass);


--
-- Name: meal_types meal_type_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.meal_types ALTER COLUMN meal_type_id SET DEFAULT nextval('public.meal_types_meal_type_id_seq'::regclass);


--
-- Name: message_attachments attachment_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.message_attachments ALTER COLUMN attachment_id SET DEFAULT nextval('public.message_attachments_attachment_id_seq'::regclass);


--
-- Name: recommendation_types rec_type_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.recommendation_types ALTER COLUMN rec_type_id SET DEFAULT nextval('public.recommendation_types_rec_type_id_seq'::regclass);


--
-- Name: roles role_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.roles ALTER COLUMN role_id SET DEFAULT nextval('public.roles_role_id_seq'::regclass);


--
-- Name: user_medications medication_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_medications ALTER COLUMN medication_id SET DEFAULT nextval('public.user_medications_medication_id_seq'::regclass);


--
-- Name: activities activities_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.activities
    ADD CONSTRAINT activities_pkey PRIMARY KEY (id);


--
-- Name: activity_types activity_types_activity_code_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.activity_types
    ADD CONSTRAINT activity_types_activity_code_key UNIQUE (activity_code);


--
-- Name: activity_types activity_types_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.activity_types
    ADD CONSTRAINT activity_types_pkey PRIMARY KEY (activity_type_id);


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
-- Name: food_categories food_categories_category_code_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.food_categories
    ADD CONSTRAINT food_categories_category_code_key UNIQUE (category_code);


--
-- Name: food_categories food_categories_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.food_categories
    ADD CONSTRAINT food_categories_pkey PRIMARY KEY (category_id);


--
-- Name: foods foods_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.foods
    ADD CONSTRAINT foods_pkey PRIMARY KEY (food_id);


--
-- Name: health_condition_types health_condition_types_condition_code_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.health_condition_types
    ADD CONSTRAINT health_condition_types_condition_code_key UNIQUE (condition_code);


--
-- Name: health_condition_types health_condition_types_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.health_condition_types
    ADD CONSTRAINT health_condition_types_pkey PRIMARY KEY (condition_id);


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
-- Name: meal_types meal_types_meal_code_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.meal_types
    ADD CONSTRAINT meal_types_meal_code_key UNIQUE (meal_code);


--
-- Name: meal_types meal_types_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.meal_types
    ADD CONSTRAINT meal_types_pkey PRIMARY KEY (meal_type_id);


--
-- Name: user_health_profiles one_profile_per_user; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_health_profiles
    ADD CONSTRAINT one_profile_per_user UNIQUE (user_id);


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
-- Name: recommendation_types recommendation_types_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.recommendation_types
    ADD CONSTRAINT recommendation_types_pkey PRIMARY KEY (rec_type_id);


--
-- Name: recommendation_types recommendation_types_rec_code_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.recommendation_types
    ADD CONSTRAINT recommendation_types_rec_code_key UNIQUE (rec_code);


--
-- Name: roles roles_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_pkey PRIMARY KEY (role_id);


--
-- Name: roles roles_role_name_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_role_name_key UNIQUE (role_name);


--
-- Name: seller_profiles seller_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.seller_profiles
    ADD CONSTRAINT seller_pkey PRIMARY KEY (seller_id);


--
-- Name: user_food_insights unique_user_food_insight; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_food_insights
    ADD CONSTRAINT unique_user_food_insight UNIQUE (user_id, food_name);


--
-- Name: user_sleep_logs unique_user_sleep_date; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_sleep_logs
    ADD CONSTRAINT unique_user_sleep_date UNIQUE (user_id, sleep_date);


--
-- Name: seller_profiles uq_seller_profiles_user_id; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.seller_profiles
    ADD CONSTRAINT uq_seller_profiles_user_id UNIQUE (user_id);


--
-- Name: users uq_user_oauth_provider; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT uq_user_oauth_provider UNIQUE (user_provider, user_provider_user_id);


--
-- Name: user_activity_logs user_activity_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_activity_logs
    ADD CONSTRAINT user_activity_logs_pkey PRIMARY KEY (activity_id);


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
-- Name: user_food_insights user_food_insights_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_food_insights
    ADD CONSTRAINT user_food_insights_pkey PRIMARY KEY (insight_id);


--
-- Name: user_glucose_readings user_glucose_readings_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_glucose_readings
    ADD CONSTRAINT user_glucose_readings_pkey PRIMARY KEY (reading_id);


--
-- Name: user_hba1c_records user_hba1c_records_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_hba1c_records
    ADD CONSTRAINT user_hba1c_records_pkey PRIMARY KEY (hba1c_id);


--
-- Name: user_health_events user_health_events_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_health_events
    ADD CONSTRAINT user_health_events_pkey PRIMARY KEY (event_id);


--
-- Name: user_health_profiles user_health_profiles_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_health_profiles
    ADD CONSTRAINT user_health_profiles_pkey PRIMARY KEY (profile_id);


--
-- Name: user_meal_items user_meal_items_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_meal_items
    ADD CONSTRAINT user_meal_items_pkey PRIMARY KEY (item_id);


--
-- Name: user_meal_logs user_meal_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_meal_logs
    ADD CONSTRAINT user_meal_logs_pkey PRIMARY KEY (meal_id);


--
-- Name: user_medication_logs user_medication_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_medication_logs
    ADD CONSTRAINT user_medication_logs_pkey PRIMARY KEY (medicationlog_id);


--
-- Name: user_medications user_medications_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_medications
    ADD CONSTRAINT user_medications_pkey PRIMARY KEY (medication_id);


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
-- Name: user_roles user_roles_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_roles
    ADD CONSTRAINT user_roles_pkey PRIMARY KEY (user_id, role_id);


--
-- Name: user_sleep_logs user_sleep_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_sleep_logs
    ADD CONSTRAINT user_sleep_logs_pkey PRIMARY KEY (sleep_id);


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
-- Name: idx_activity_logs_duration; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_activity_logs_duration ON public.user_activity_logs USING btree (duration_minutes);


--
-- Name: idx_activity_logs_intensity; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_activity_logs_intensity ON public.user_activity_logs USING btree (intensity);


--
-- Name: idx_activity_logs_source; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_activity_logs_source ON public.user_activity_logs USING btree (source);


--
-- Name: idx_activity_logs_timestamp; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_activity_logs_timestamp ON public.user_activity_logs USING btree (activity_timestamp DESC);


--
-- Name: idx_activity_logs_user_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_activity_logs_user_id ON public.user_activity_logs USING btree (user_id);


--
-- Name: idx_activity_logs_user_timestamp; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_activity_logs_user_timestamp ON public.user_activity_logs USING btree (user_id, activity_timestamp DESC);


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
-- Name: idx_glucose_readings_flagged; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_glucose_readings_flagged ON public.user_glucose_readings USING btree (is_flagged) WHERE (is_flagged = true);


--
-- Name: idx_glucose_readings_source; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_glucose_readings_source ON public.user_glucose_readings USING btree (source);


--
-- Name: idx_glucose_readings_timestamp; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_glucose_readings_timestamp ON public.user_glucose_readings USING btree (reading_timestamp DESC);


--
-- Name: idx_glucose_readings_type; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_glucose_readings_type ON public.user_glucose_readings USING btree (reading_type);


--
-- Name: idx_glucose_readings_user_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_glucose_readings_user_id ON public.user_glucose_readings USING btree (user_id);


--
-- Name: idx_glucose_readings_user_timestamp; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_glucose_readings_user_timestamp ON public.user_glucose_readings USING btree (user_id, reading_timestamp DESC);


--
-- Name: idx_glucose_readings_value; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_glucose_readings_value ON public.user_glucose_readings USING btree (glucose_value);


--
-- Name: idx_hba1c_records_date; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_hba1c_records_date ON public.user_hba1c_records USING btree (test_date DESC);


--
-- Name: idx_hba1c_records_trend; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_hba1c_records_trend ON public.user_hba1c_records USING btree (trend);


--
-- Name: idx_hba1c_records_user_date; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_hba1c_records_user_date ON public.user_hba1c_records USING btree (user_id, test_date DESC);


--
-- Name: idx_hba1c_records_user_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_hba1c_records_user_id ON public.user_hba1c_records USING btree (user_id);


--
-- Name: idx_health_events_date; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_health_events_date ON public.user_health_events USING btree (event_date DESC);


--
-- Name: idx_health_events_severity; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_health_events_severity ON public.user_health_events USING btree (severity);


--
-- Name: idx_health_events_type; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_health_events_type ON public.user_health_events USING btree (event_type);


--
-- Name: idx_health_events_user_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_health_events_user_id ON public.user_health_events USING btree (user_id);


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
-- Name: idx_meal_items_category; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_meal_items_category ON public.user_meal_items USING btree (food_category);


--
-- Name: idx_meal_items_food_name; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_meal_items_food_name ON public.user_meal_items USING btree (food_name);


--
-- Name: idx_meal_items_meal_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_meal_items_meal_id ON public.user_meal_items USING btree (meal_id);


--
-- Name: idx_meal_logs_tags; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_meal_logs_tags ON public.user_meal_logs USING gin (tags);


--
-- Name: idx_meal_logs_timestamp; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_meal_logs_timestamp ON public.user_meal_logs USING btree (meal_timestamp DESC);


--
-- Name: idx_meal_logs_type; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_meal_logs_type ON public.user_meal_logs USING btree (meal_type_id);


--
-- Name: idx_meal_logs_user_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_meal_logs_user_id ON public.user_meal_logs USING btree (user_id);


--
-- Name: idx_meal_logs_user_timestamp; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_meal_logs_user_timestamp ON public.user_meal_logs USING btree (user_id, meal_timestamp DESC);


--
-- Name: idx_medication_logs_timestamp; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_medication_logs_timestamp ON public.user_medication_logs USING btree ("timestamp" DESC);


--
-- Name: idx_medication_logs_user_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_medication_logs_user_id ON public.user_medication_logs USING btree (user_id);


--
-- Name: idx_medication_logs_user_timestamp; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_medication_logs_user_timestamp ON public.user_medication_logs USING btree (user_id, "timestamp" DESC);


--
-- Name: idx_medication_type_user_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_medication_type_user_id ON public.user_medications USING btree (medication_type);


--
-- Name: idx_medication_user_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_medication_user_id ON public.user_medications USING btree (user_id);


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
-- Name: idx_seller_profiles_store_name; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_seller_profiles_store_name ON public.seller_profiles USING btree (store_name);


--
-- Name: idx_sleep_logs_date; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_sleep_logs_date ON public.user_sleep_logs USING btree (sleep_date DESC);


--
-- Name: idx_sleep_logs_quality; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_sleep_logs_quality ON public.user_sleep_logs USING btree (quality_rating);


--
-- Name: idx_sleep_logs_user_date; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_sleep_logs_user_date ON public.user_sleep_logs USING btree (user_id, sleep_date DESC);


--
-- Name: idx_sleep_logs_user_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_sleep_logs_user_id ON public.user_sleep_logs USING btree (user_id);


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
-- Name: idx_user_food_insights_favorite; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_user_food_insights_favorite ON public.user_food_insights USING btree (is_favorite);


--
-- Name: idx_user_food_insights_score; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_user_food_insights_score ON public.user_food_insights USING btree (health_score);


--
-- Name: idx_user_food_insights_trigger; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_user_food_insights_trigger ON public.user_food_insights USING btree (is_trigger_food) WHERE (is_trigger_food = true);


--
-- Name: idx_user_food_insights_user_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_user_food_insights_user_id ON public.user_food_insights USING btree (user_id);


--
-- Name: idx_user_health_profiles_condition; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_user_health_profiles_condition ON public.user_health_profiles USING btree (condition_id);


--
-- Name: idx_user_health_profiles_experience; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_user_health_profiles_experience ON public.user_health_profiles USING btree (app_experience);


--
-- Name: idx_user_health_profiles_user_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_user_health_profiles_user_id ON public.user_health_profiles USING btree (user_id);


--
-- Name: idx_user_roles_role_id; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX idx_user_roles_role_id ON public.user_roles USING btree (role_id);


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

CREATE INDEX idx_users_unverified ON public.users USING btree (is_email_verified, created_at) WHERE (is_email_verified = false);


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
-- Name: user_glucose_readings trigger_calculate_glucose_trend; Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER trigger_calculate_glucose_trend BEFORE INSERT OR UPDATE ON public.user_glucose_readings FOR EACH ROW EXECUTE FUNCTION public.calculate_glucose_trend();


--
-- Name: user_hba1c_records trigger_calculate_hba1c_metrics; Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER trigger_calculate_hba1c_metrics BEFORE INSERT OR UPDATE ON public.user_hba1c_records FOR EACH ROW EXECUTE FUNCTION public.calculate_hba1c_trend();


--
-- Name: seller_profiles trigger_seller_profiles_updated_at; Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER trigger_seller_profiles_updated_at BEFORE UPDATE ON public.seller_profiles FOR EACH ROW EXECUTE FUNCTION public.update_seller_profiles_updated_at();


--
-- Name: user_hba1c_records trigger_update_profile_after_hba1c; Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER trigger_update_profile_after_hba1c AFTER INSERT OR UPDATE ON public.user_hba1c_records FOR EACH ROW EXECUTE FUNCTION public.update_user_profile_with_latest_hba1c();


--
-- Name: user_addresses trigger_user_addresses_updated_at; Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER trigger_user_addresses_updated_at BEFORE UPDATE ON public.user_addresses FOR EACH ROW EXECUTE FUNCTION public.update_user_addresses_updated_at();


--
-- Name: user_health_events update_updated_at(); Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER "update_updated_at()" BEFORE UPDATE ON public.user_health_events FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: user_medication_logs update_updated_at(); Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER "update_updated_at()" BEFORE UPDATE ON public.user_medication_logs FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: user_medications update_updated_at(); Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER "update_updated_at()" BEFORE UPDATE ON public.user_medications FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: user_health_profiles update_user_health_profiles_updated_at; Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER update_user_health_profiles_updated_at BEFORE UPDATE ON public.user_health_profiles FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: users update_users_updated_at; Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON public.users FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: users_auth update_users_updated_at; Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON public.users_auth FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: activities activities_activity_code_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.activities
    ADD CONSTRAINT activities_activity_code_fkey FOREIGN KEY (activity_code) REFERENCES public.activity_types(activity_code) ON DELETE CASCADE;


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
-- Name: seller_profiles fk_seller_profiles_user_id; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.seller_profiles
    ADD CONSTRAINT fk_seller_profiles_user_id FOREIGN KEY (user_id) REFERENCES public.users(user_id) ON DELETE CASCADE;


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
-- Name: user_activity_logs user_activity_logs_activity_code_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_activity_logs
    ADD CONSTRAINT user_activity_logs_activity_code_fkey FOREIGN KEY (activity_code) REFERENCES public.activity_types(activity_code);


--
-- Name: user_activity_logs user_activity_logs_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_activity_logs
    ADD CONSTRAINT user_activity_logs_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id) ON DELETE CASCADE;


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
-- Name: user_food_insights user_food_insights_food_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_food_insights
    ADD CONSTRAINT user_food_insights_food_id_fkey FOREIGN KEY (food_id) REFERENCES public.foods(food_id) ON DELETE SET NULL;


--
-- Name: user_food_insights user_food_insights_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_food_insights
    ADD CONSTRAINT user_food_insights_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id) ON DELETE CASCADE;


--
-- Name: user_glucose_readings user_glucose_readings_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_glucose_readings
    ADD CONSTRAINT user_glucose_readings_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id) ON DELETE CASCADE;


--
-- Name: user_hba1c_records user_hba1c_records_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_hba1c_records
    ADD CONSTRAINT user_hba1c_records_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id) ON DELETE CASCADE;


--
-- Name: user_health_events user_health_events_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_health_events
    ADD CONSTRAINT user_health_events_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id) ON DELETE CASCADE;


--
-- Name: user_health_profiles user_health_profiles_condition_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_health_profiles
    ADD CONSTRAINT user_health_profiles_condition_id_fkey FOREIGN KEY (condition_id) REFERENCES public.health_condition_types(condition_id);


--
-- Name: user_health_profiles user_health_profiles_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_health_profiles
    ADD CONSTRAINT user_health_profiles_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id) ON DELETE CASCADE;


--
-- Name: user_meal_logs user_meal_logs_meal_type_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_meal_logs
    ADD CONSTRAINT user_meal_logs_meal_type_id_fkey FOREIGN KEY (meal_type_id) REFERENCES public.meal_types(meal_type_id);


--
-- Name: user_meal_logs user_meal_logs_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_meal_logs
    ADD CONSTRAINT user_meal_logs_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id) ON DELETE CASCADE;


--
-- Name: user_medication_logs user_medication_logs_medication_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_medication_logs
    ADD CONSTRAINT user_medication_logs_medication_id_fkey FOREIGN KEY (medication_id) REFERENCES public.user_medications(medication_id);


--
-- Name: user_medication_logs user_medication_logs_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_medication_logs
    ADD CONSTRAINT user_medication_logs_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id) ON DELETE CASCADE;


--
-- Name: user_medications user_medications_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_medications
    ADD CONSTRAINT user_medications_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id) ON DELETE CASCADE;


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
-- Name: user_roles user_roles_role_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_roles
    ADD CONSTRAINT user_roles_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.roles(role_id) ON DELETE CASCADE;


--
-- Name: user_roles user_roles_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_roles
    ADD CONSTRAINT user_roles_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id) ON DELETE CASCADE;


--
-- Name: user_sleep_logs user_sleep_logs_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_sleep_logs
    ADD CONSTRAINT user_sleep_logs_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id) ON DELETE CASCADE;


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
